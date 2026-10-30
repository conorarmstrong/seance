//! Data source abstractions for forensic analysis.
//!
//! This module provides the [`DataSource`] trait and related types that enable
//! uniform access to evidence data regardless of its physical location - whether
//! in a raw file, inside an E01 container, or a region within a disk image.
//!
//! # Design Philosophy
//!
//! All data access in Seance goes through [`DataSource`] implementations, never
//! direct file paths. This provides:
//!
//! - **Uniform access**: Same interface for files, disk images, and containers
//! - **Lazy loading**: Data is read on demand, not loaded into memory
//! - **Thread safety**: Stateless `read_at()` enables parallel processing
//! - **Composition**: Data sources can be stacked (buffered, windowed, etc.)
//!
//! # Common Patterns
//!
//! ```rust,ignore
//! use seance_core::data_source::{DataSource, FileDataSource, SourceCursor};
//! use std::io::Read;
//! use std::sync::Arc;
//!
//! // Create a data source from a file
//! let source: Arc<dyn DataSource> = Arc::new(
//!     FileDataSource::new("evidence.dd".into())?
//! );
//!
//! // Random access read
//! let mut buf = [0u8; 512];
//! source.read_at(0, &mut buf)?;
//!
//! // Sequential access via SourceCursor
//! let mut cursor = SourceCursor::new(source.clone());
//! cursor.read_to_end(&mut Vec::new())?;
//! ```

use lru::LruCache;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use tracing::warn;

#[cfg(unix)]
use std::os::unix::fs::FileExt;

/// The fundamental trait for reading forensic evidence data.
///
/// All analysis modules access data through this trait, enabling uniform handling
/// of files, disk images, container formats, and virtual views.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync`. The `read_at()` method is deliberately
/// stateless to enable safe concurrent access from multiple threads without
/// external synchronization.
///
/// # Implementation Notes
///
/// - `read_at()` should return 0 bytes when `offset >= size()`
/// - Implementations should handle partial reads at end-of-data gracefully
/// - For performance-critical paths, consider using platform-specific APIs
///   like `pread()` on Unix to avoid lock contention
///
/// # Example Implementation
///
/// ```rust,ignore
/// use seance_core::data_source::DataSource;
/// use std::io;
///
/// #[derive(Debug)]
/// struct MemorySource {
///     data: Vec<u8>,
/// }
///
/// impl DataSource for MemorySource {
///     fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
///         let offset = offset as usize;
///         if offset >= self.data.len() {
///             return Ok(0);
///         }
///         let to_read = std::cmp::min(buf.len(), self.data.len() - offset);
///         buf[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
///         Ok(to_read)
///     }
///
///     fn size(&self) -> u64 {
///         self.data.len() as u64
///     }
/// }
/// ```
pub trait DataSource: Send + Sync + Debug {
    /// Reads bytes at a specific offset within this data source.
    ///
    /// This method is stateless - it does not modify any internal position state,
    /// allowing safe concurrent reads from multiple threads.
    ///
    /// # Arguments
    ///
    /// * `offset` - Byte offset from the start of the data source
    /// * `buf` - Buffer to read data into
    ///
    /// # Returns
    ///
    /// * `Ok(n)` - Number of bytes read (may be less than `buf.len()`)
    /// * `Ok(0)` - End of data reached or `offset >= size()`
    /// * `Err(_)` - I/O error occurred
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Returns the total size of this data source in bytes.
    fn size(&self) -> u64;

    /// Returns the underlying file path if this source maps directly to a file.
    ///
    /// Used for modules that must interface with external tools requiring file paths.
    /// Most implementations return `None`.
    fn get_underlying_path(&self) -> Option<PathBuf> {
        None
    }

    /// Opens a sibling source whose name is this source's name with `suffix`
    /// appended — e.g. `-wal` for a SQLite write-ahead log, or `-journal` for a
    /// rollback journal.
    ///
    /// Returns `None` when the source has no notion of siblings (a bare byte
    /// buffer) or the sibling does not exist. This lets a parser reach a
    /// database's `-wal`/`-journal` even when the file lives *inside a container*
    /// (e.g. a ZIP entry or an iOS backup) rather than on the local filesystem,
    /// where a path-based lookup cannot see it. Most implementations return
    /// `None`; container-entry and file-backed sources override it.
    fn open_sibling(&self, _suffix: &str) -> Option<Arc<dyn DataSource>> {
        None
    }

    /// Can this source look for siblings at all?
    ///
    /// `open_sibling` returning `None` answers two different questions with one
    /// word: *there is no such sibling*, and *this kind of source cannot look*.
    /// For a SQLite database those are opposite findings — a database with no
    /// `-wal` has been checkpointed and is whole, while one whose `-wal` could
    /// not be reached is missing its newest rows with nothing to show for it
    /// (HUNT-101). A source that can enumerate its neighbours says so here, and
    /// a caller that finds nothing can then tell which answer it got.
    fn supports_siblings(&self) -> bool {
        false
    }

    /// Opens a source at a path **relative to this source's directory** —
    /// `54/54e5648b…` beside an iOS backup's `Manifest.db`, say — for the
    /// case where the neighbour is not a suffix of this name (HUNT-109).
    ///
    /// `relative` is `/`-separated and must not climb (`..` is refused) —
    /// a manifest names files beside or below itself, never above. Returns
    /// `None` when the source cannot look (see [`Self::supports_siblings`],
    /// which answers for both kinds of neighbour) or the file is not there.
    fn open_relative(&self, _relative: &str) -> Option<Arc<dyn DataSource>> {
        None
    }

    /// `true` when `relative` names a neighbour that was present but
    /// deliberately **withheld** — a name that occurs twice among the live
    /// entries of one directory is not chosen between (HUNT-195). A caller
    /// that finds `open_relative` returning `None` can then say "present and
    /// withheld" rather than "not there". Matched case-insensitively.
    fn relative_withheld(&self, _relative: &str) -> bool {
        false
    }

    /// Opens a source at a plain relative path under an **ancestor** of this
    /// source's directory: `levels` directories up (at most
    /// [`MAX_ANCESTOR_LEVELS`]), then `relative` down.
    ///
    /// This is how an Apple unified log reaches the rest of its tree: a
    /// `Persist/….tracev3` finds its format strings at `../<XX>/<rest>` in a
    /// `.logarchive`, or at `../../uuidtext/<XX>/<rest>` under
    /// `/var/db/diagnostics`. `levels` is bounded and `relative` must be plain
    /// (see [`relative_path_is_plain`]), so the reach is a fixed, stated
    /// distance and never a free walk of the file system. `levels == 0` is the
    /// same as [`Self::open_relative`].
    ///
    /// Returns `None` when the source cannot look (see
    /// [`Self::supports_ancestors`]), the climb leaves the container it is in,
    /// or the file is not there. A file inside a disk image answers `None`
    /// today: its tree is not reachable from the source, and a caller says so.
    fn open_from_ancestor(&self, _levels: usize, _relative: &str) -> Option<Arc<dyn DataSource>> {
        None
    }

    /// The names of the files directly in the directory `relative_dir` under
    /// an ancestor of this source's directory — the same bounded climb as
    /// [`Self::open_from_ancestor`] — sorted, sub-directories left out.
    ///
    /// A unified log needs this where names cannot be predicted: timesync
    /// files keep sequence names after the oldest are rotated away, so the
    /// first one present may be far along the sequence (HUNT-272), and an
    /// oversize entry may sit in another `.tracev3` of the tree (HUNT-271).
    ///
    /// Returns `None` when the source cannot list (the default), the
    /// directory is not there, or it holds more than [`MAX_LISTED_NAMES`]
    /// files — a caller then falls back to what it can open by name, and
    /// says which it did. `Some(vec![])` is an empty directory.
    fn list_from_ancestor(&self, _levels: usize, _relative_dir: &str) -> Option<Vec<String>> {
        None
    }

    /// Can [`Self::open_from_ancestor`] look at all? Separates "the tree is not
    /// there" from "this kind of source cannot reach its tree".
    fn supports_ancestors(&self) -> bool {
        false
    }

    /// The whole content, when this source is nothing but bytes held in memory.
    ///
    /// A queue that parks an artifact on disk keeps its data source resident,
    /// because a file handle cannot be written to a file. A source that *is*
    /// its bytes — a blob carried out of a property list, an entry inflated
    /// from an archive — can be, and answers here so the queue can park the
    /// bytes too and re-materialise them when the artifact is taken (HUNT-114:
    /// a walk of 40,000 files spilled 190,000 artifacts and held every
    /// carried-out blob in memory behind them). Every other source answers
    /// `None` and stays resident.
    fn resident_bytes(&self) -> Option<&[u8]> {
        None
    }

    /// Project the logical range `[offset, offset + len)` in this source down to
    /// the physical extents it occupies on the backing device image.
    ///
    /// Composable sources override this to recurse toward the backing store: a
    /// [`WindowSource`] shifts by its start and recurses; a [`RunListDataSource`]
    /// splits the range across its runs and recurses per piece (so a contiguous
    /// logical range projects to *multiple* device extents when the backing is
    /// fragmented, including fragmentation nested through a container file). A
    /// terminal device image ([`FileDataSource`], [`DeviceImageSource`]) returns
    /// its own offset as an exact device extent.
    ///
    /// The default is [`PhysicalMap::opaque`]: a source with no known linear
    /// mapping to a device (in-memory bytes, reconstructed content, or any
    /// unrecognized transform) honestly reports "no device backing" rather than
    /// inventing a false-precision offset.
    fn physical_map(&self, _offset: u64, len: u64) -> PhysicalMap {
        PhysicalMap::opaque(len)
    }
}

/// The most file names [`DataSource::list_from_ancestor`] returns; a
/// directory holding more is not listed at all rather than listed in part.
pub const MAX_LISTED_NAMES: usize = 65_536;

/// The furthest [`DataSource::open_from_ancestor`] climbs: enough for
/// `/var/db/diagnostics/Persist/x.tracev3` to reach `/var/db/uuidtext`, and no
/// further.
pub const MAX_ANCESTOR_LEVELS: usize = 3;

/// The whole of `read_at` for a source whose bytes are produced by decrypting a
/// range on demand (LUKS, BitLocker XTS and CBC).
///
/// Nothing is read at or past `plaintext_size`; a request is clamped to it; the
/// bytes `decrypt(offset, want)` returns fill the front of `buf`, and a failure
/// is an `io::Error` rather than a short or zero-filled read, so a wrong key or
/// a damaged sector is never served as content.
pub fn read_decrypted_range<E: std::fmt::Display>(
    plaintext_size: u64,
    offset: u64,
    buf: &mut [u8],
    decrypt: impl FnOnce(u64, usize) -> Result<Vec<u8>, E>,
) -> std::io::Result<usize> {
    if offset >= plaintext_size || buf.is_empty() {
        return Ok(0);
    }
    let want = std::cmp::min(buf.len() as u64, plaintext_size - offset) as usize;
    let plain = decrypt(offset, want).map_err(|e| std::io::Error::other(e.to_string()))?;
    buf[..want].copy_from_slice(&plain[..want]);
    Ok(want)
}

/// The `levels`-th ancestor of a `/`-separated entry name's directory, as a
/// prefix ending in `/` (or empty for the root), when the climb stays inside
/// the name. Shared by container-entry sources.
pub fn ancestor_prefix(entry_name: &str, levels: usize) -> Option<String> {
    if levels > MAX_ANCESTOR_LEVELS {
        return None;
    }
    let mut parts: Vec<&str> = entry_name.split('/').collect();
    parts.pop(); // the entry's own name
    if levels > parts.len() {
        return None;
    }
    parts.truncate(parts.len() - levels);
    Some(if parts.is_empty() {
        String::new()
    } else {
        format!("{}/", parts.join("/"))
    })
}

/// Is `relative` a path [`DataSource::open_relative`] may resolve — non-empty,
/// no absolute root, no `.`/`..` components, no empty component?
pub fn relative_path_is_plain(relative: &str) -> bool {
    !relative.is_empty()
        && !relative.starts_with('/')
        && !relative.contains('\\')
        && relative
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

/// How precisely a logical byte range can be located on the backing device
/// image, taken as the worst case across the whole projection chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentPrecision {
    /// Byte-exact device offset; the bytes there are the artifact's bytes
    /// verbatim (raw window / partition / filesystem / carve / decoded image).
    Exact,
    /// Byte-exact position, but the on-disk bytes are encrypted at rest
    /// (LUKS/BitLocker) and require the key to read.
    Encrypted,
    /// Backing is compressed; the position is known only to the granularity of
    /// the compression unit, not the individual logical byte.
    Compressed,
    /// No single device range: content is reconstructed from scattered
    /// locations (VSS), decompressed, or materialized in memory.
    Synthetic,
}

impl ExtentPrecision {
    /// Rank for worst-case combination (higher = less precise).
    fn rank(self) -> u8 {
        match self {
            ExtentPrecision::Exact => 0,
            ExtentPrecision::Encrypted => 1,
            ExtentPrecision::Compressed => 2,
            ExtentPrecision::Synthetic => 3,
        }
    }

    /// The less precise of the two precisions.
    pub fn worst(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    /// Lower-case identifier for JSON/display.
    pub fn as_str(self) -> &'static str {
        match self {
            ExtentPrecision::Exact => "exact",
            ExtentPrecision::Encrypted => "encrypted",
            ExtentPrecision::Compressed => "compressed",
            ExtentPrecision::Synthetic => "synthetic",
        }
    }
}

/// Which source an extent's offset is measured in.
///
/// Mirrors [`BackingSource`] in `seance_memory`, deliberately: the memory layer
/// already had to distinguish "in the image" from "in a file attached beside
/// it" when pagefile support landed, and a projection that used a second
/// vocabulary for the same distinction would be one more thing to keep in step.
///
/// # Why an index rather than a name
///
/// [`PhysicalExtent`] is `Copy` and is held by the thousand for a fragmented
/// file, so it cannot carry a `String`. The names live once on
/// [`PhysicalMap::auxiliary_sources`] and each extent refers to one by index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExtentSource {
    /// The backing device image the artifact was read from.
    #[default]
    Device,
    /// A file carried alongside the image — a Windows `pagefile.sys`, a Linux
    /// swap device. The offset is into **that file**, not into the image.
    Auxiliary(u16),
}

/// One contiguous region of an artifact's bytes on its backing source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalExtent {
    /// Byte offset in the source named by [`PhysicalExtent::source`], or `None`
    /// for a sparse (hole) region, or a region with no backing at all
    /// (synthetic content).
    pub device_offset: Option<u64>,
    /// Length of the region in bytes.
    pub length: u64,
    /// Which source [`PhysicalExtent::device_offset`] is measured in.
    ///
    /// # What this exists to prevent
    ///
    /// A page the kernel swapped out resolves to real bytes, at a real offset,
    /// in `pagefile.sys` — a *different file* from the memory image. Publishing
    /// that offset as a plain `device_offset` would send an examiner who seeks
    /// to it in the image to an unrelated page and tell them it was the one
    /// they asked for. Before this field existed the only honest option was to
    /// report such an extent as having no backing at all, which understated
    /// what had actually been recovered.
    pub source: ExtentSource,
}

impl PhysicalExtent {
    /// `length` bytes at `device_offset` on the backing device image.
    pub fn device(device_offset: u64, length: u64) -> Self {
        Self {
            device_offset: Some(device_offset),
            length,
            source: ExtentSource::Device,
        }
    }

    /// `length` bytes with no backing: a sparse hole, or synthetic content.
    pub fn hole(length: u64) -> Self {
        Self {
            device_offset: None,
            length,
            source: ExtentSource::Device,
        }
    }

    /// `length` bytes at `offset` in the auxiliary source at `index`.
    pub fn auxiliary(index: u16, offset: u64, length: u64) -> Self {
        Self {
            device_offset: Some(offset),
            length,
            source: ExtentSource::Auxiliary(index),
        }
    }

    /// True when these bytes came from somewhere other than the device image.
    pub fn is_auxiliary(&self) -> bool {
        matches!(self.source, ExtentSource::Auxiliary(_))
    }
}

/// The physical location of a logical byte range, resolved through the whole
/// container/filesystem chain to the backing device image.
#[derive(Debug, Clone)]
pub struct PhysicalMap {
    /// Extents in logical order (fragmentation-aware).
    pub extents: Vec<PhysicalExtent>,
    /// Worst-case precision across the projection.
    pub precision: ExtentPrecision,
    /// Names of the auxiliary sources any extent refers to, indexed by
    /// [`ExtentSource::Auxiliary`].
    ///
    /// Empty for the ordinary case, where everything came off the device image.
    /// A name here is what lets a report say *which* pagefile a byte was
    /// recovered from — "a page from `\\.\C:\pagefile.sys`" rather than an
    /// unexplained offset that matches nothing in the image.
    pub auxiliary_sources: Vec<String>,
}

impl PhysicalMap {
    /// An empty map at the given precision.
    pub fn empty(precision: ExtentPrecision) -> Self {
        Self {
            extents: Vec::new(),
            precision,
            auxiliary_sources: Vec::new(),
        }
    }

    /// A map of `extents` at `precision`, all on the device image.
    pub fn on_device(extents: Vec<PhysicalExtent>, precision: ExtentPrecision) -> Self {
        Self {
            extents,
            precision,
            auxiliary_sources: Vec::new(),
        }
    }

    /// A single opaque region of `len` bytes: no device backing (in-memory or
    /// reconstructed content).
    pub fn opaque(len: u64) -> Self {
        Self {
            extents: vec![PhysicalExtent::hole(len)],
            precision: ExtentPrecision::Synthetic,
            auxiliary_sources: Vec::new(),
        }
    }

    /// A single exact device extent at `device_offset` of `len` bytes.
    pub fn exact(device_offset: u64, len: u64) -> Self {
        Self {
            extents: vec![PhysicalExtent::device(device_offset, len)],
            precision: ExtentPrecision::Exact,
            auxiliary_sources: Vec::new(),
        }
    }

    /// Record `name` as an auxiliary source and return the index to refer to it
    /// by, reusing the index if it is already known.
    ///
    /// Returns `None` when the table is full (more than `u16::MAX` distinct
    /// sources). A caller that cannot get an index must not fall back to
    /// reporting a device offset: the offset would then be read against the
    /// wrong file.
    pub fn intern_auxiliary(&mut self, name: &str) -> Option<u16> {
        if let Some(existing) = self.auxiliary_sources.iter().position(|n| n == name) {
            return u16::try_from(existing).ok();
        }
        let index = u16::try_from(self.auxiliary_sources.len()).ok()?;
        self.auxiliary_sources.push(name.to_string());
        Some(index)
    }

    /// Append another map's extents to this one, rebasing its auxiliary source
    /// indices onto this map's table.
    ///
    /// Projections nest — a file inside a run-list inside a container — and each
    /// level builds its own map. An extent's [`ExtentSource::Auxiliary`] index
    /// is only meaningful against the map it came from, so concatenating the
    /// extent lists without rebasing would silently re-point a pagefile-backed
    /// extent at whatever source happened to sit at that index in the parent.
    /// That is a wrong answer of the worst kind: it names a real file and a real
    /// offset, and is confidently about the wrong one.
    pub fn absorb(&mut self, other: PhysicalMap) {
        let remap: Vec<Option<u16>> = other
            .auxiliary_sources
            .iter()
            .map(|name| self.intern_auxiliary(name))
            .collect();

        for mut extent in other.extents {
            if let ExtentSource::Auxiliary(index) = extent.source {
                match remap.get(index as usize).copied().flatten() {
                    Some(rebased) => extent.source = ExtentSource::Auxiliary(rebased),
                    // The index names no source we can resolve. The bytes exist
                    // but we can no longer say where, so the extent is demoted
                    // to "no backing" rather than left pointing at an offset
                    // that would be read against the device image.
                    None => {
                        extent.device_offset = None;
                        extent.source = ExtentSource::Device;
                        self.precision = self.precision.worst(ExtentPrecision::Synthetic);
                    }
                }
            }
            self.extents.push(extent);
        }

        self.precision = self.precision.worst(other.precision);
    }

    /// Total length covered by all extents.
    ///
    /// Saturates rather than wraps: an examiner reading "this file occupies
    /// 4 KiB" when its corrupt extent list sums past `u64::MAX` would be told
    /// the opposite of the truth, so an impossible total is reported as
    /// `u64::MAX` (BUG-093 family).
    pub fn total_len(&self) -> u64 {
        self.extents
            .iter()
            .fold(0u64, |acc, e| acc.saturating_add(e.length))
    }

    /// Total length that is actually device-backed (excludes sparse/synthetic).
    ///
    /// Saturates for the same reason as [`PhysicalMap::total_len`].
    pub fn located_len(&self) -> u64 {
        self.extents
            .iter()
            .filter(|e| e.device_offset.is_some())
            .fold(0u64, |acc, e| acc.saturating_add(e.length))
    }

    /// Coalesce adjacent extents that are contiguous on the device (or both
    /// sparse), producing the minimal fragmentation-aware list.
    ///
    /// Contiguity and merging both use checked arithmetic. An extent list from
    /// hostile or corrupt filesystem metadata can place `device_offset +
    /// length` past `u64::MAX`; wrapping there would either declare two
    /// unrelated regions adjacent (so the map claims bytes come from somewhere
    /// they do not) or fold a merged length down to a small number (so a
    /// download/hash silently loses the tail). Both are refused: an extent that
    /// cannot be proven adjacent stays a separate extent, which is at worst a
    /// less compact but still truthful map (BUG-128 / BUG-093 family).
    pub fn coalesce(mut self) -> Self {
        let mut out: Vec<PhysicalExtent> = Vec::with_capacity(self.extents.len());
        for e in self.extents.drain(..) {
            if e.length == 0 {
                continue;
            }
            if let Some(last) = out.last_mut() {
                let contiguous = match (last.device_offset, e.device_offset) {
                    (Some(a), Some(b)) => a.checked_add(last.length) == Some(b),
                    (None, None) => true,
                    _ => false,
                };
                if contiguous {
                    if let Some(merged) = last.length.checked_add(e.length) {
                        last.length = merged;
                        continue;
                    }
                    // Merged length would overflow u64: keep the extents
                    // separate rather than wrap to a small, wrong length.
                }
            }
            out.push(e);
        }
        self.extents = out;
        self
    }
}

/// A [`DataSource`] implementation backed by a file on the local filesystem.
///
/// This is the most common data source for loading evidence files directly.
/// Reads are positional (`pread()` on Unix, `seek_read` on Windows) and take no
/// lock once the file is open, so parallel workers reading one file do not queue.
///
/// # Example
///
/// ```rust,ignore
/// use seance_core::data_source::FileDataSource;
///
/// let source = FileDataSource::new("evidence.dd".into())?;
/// println!("File size: {} bytes", source.size());
/// ```
pub struct FileDataSource {
    /// `None` until the first read for a source made with [`Self::deferred`];
    /// a walk that makes tens of thousands of these must not hold a
    /// descriptor for each (HUNT-114).
    file: OnceLock<File>,
    path: PathBuf,
    size: u64,
}

impl FileDataSource {
    /// Open `path` now and keep it open.
    pub fn new(path: PathBuf) -> io::Result<Self> {
        let file = File::open(&path)?;
        let metadata = file.metadata()?;
        Ok(Self {
            file: OnceLock::from(file),
            path,
            size: metadata.len(),
        })
    }

    /// Size `path` now, open it at the first read.
    ///
    /// For the directory walker, which produces one source per file in a tree
    /// before any is read: forty thousand open descriptors is past the default
    /// `ulimit -n` on most hosts, and past it `File::open` fails with *Too many
    /// open files* — which, swallowed, leaves a file entry with no content and
    /// nothing saying why. Stat cannot run out of descriptors.
    pub fn deferred(path: PathBuf) -> io::Result<Self> {
        let metadata = std::fs::metadata(&path)?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", path.display()),
            ));
        }
        Ok(Self {
            file: OnceLock::new(),
            path,
            size: metadata.len(),
        })
    }

    /// The open file, opening it on first use. Two threads racing the first
    /// read may both open it; one handle wins and the other is closed.
    fn file(&self) -> io::Result<&File> {
        if let Some(file) = self.file.get() {
            return Ok(file);
        }
        let opened = File::open(&self.path)?;
        Ok(self.file.get_or_init(|| opened))
    }
}

impl Debug for FileDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileDataSource")
            .field("path", &self.path)
            .field("size", &self.size)
            .finish()
    }
}

impl DataSource for FileDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let file = self.file()?;
        // Positional reads share no cursor, so no lock is needed.
        #[cfg(unix)]
        {
            file.read_at(buf, offset)
        }

        #[cfg(windows)]
        {
            std::os::windows::fs::FileExt::seek_read(file, buf, offset)
        }
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn get_underlying_path(&self) -> Option<PathBuf> {
        Some(self.path.clone())
    }

    fn supports_siblings(&self) -> bool {
        true
    }

    fn supports_ancestors(&self) -> bool {
        true
    }

    fn open_from_ancestor(&self, levels: usize, relative: &str) -> Option<Arc<dyn DataSource>> {
        if levels > MAX_ANCESTOR_LEVELS || !relative_path_is_plain(relative) {
            return None;
        }
        let mut dir = self.path.parent()?;
        for _ in 0..levels {
            dir = dir.parent()?;
        }
        let target = dir.join(relative);
        if !target.is_file() {
            return None;
        }
        FileDataSource::new(target)
            .ok()
            .map(|s| Arc::new(s) as Arc<dyn DataSource>)
    }

    fn list_from_ancestor(&self, levels: usize, relative_dir: &str) -> Option<Vec<String>> {
        if levels > MAX_ANCESTOR_LEVELS
            || !(relative_dir.is_empty() || relative_path_is_plain(relative_dir))
        {
            return None;
        }
        let mut dir = self.path.parent()?;
        for _ in 0..levels {
            dir = dir.parent()?;
        }
        let dir = dir.join(relative_dir);
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&dir).ok()? {
            let entry = entry.ok()?;
            // `is_file` follows a symbolic link, as `open_from_ancestor` does.
            // A name that is not UTF-8 cannot be opened by a `&str` path, so
            // it is not offered.
            if !entry.path().is_file() {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            names.push(name);
            if names.len() > MAX_LISTED_NAMES {
                return None;
            }
        }
        names.sort();
        Some(names)
    }

    fn open_relative(&self, relative: &str) -> Option<Arc<dyn DataSource>> {
        if !relative_path_is_plain(relative) {
            return None;
        }
        let target = self.path.parent()?.join(relative);
        if !target.is_file() {
            return None;
        }
        FileDataSource::new(target)
            .ok()
            .map(|s| Arc::new(s) as Arc<dyn DataSource>)
    }

    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        // Append the suffix to the full path ("/e/1.db" + "-wal" -> "/e/1.db-wal").
        let sibling = PathBuf::from(format!("{}{}", self.path.display(), suffix));
        if !sibling.is_file() {
            return None;
        }
        FileDataSource::new(sibling)
            .ok()
            .map(|s| Arc::new(s) as Arc<dyn DataSource>)
    }

    fn physical_map(&self, offset: u64, len: u64) -> PhysicalMap {
        // A raw file / device image: its own offset IS the device coordinate.
        let avail = self.size.saturating_sub(offset);
        PhysicalMap::exact(offset, len.min(avail))
    }
}

/// A view into a contiguous subset of a parent [`DataSource`].
///
/// Used to create bounded views, such as extracting a partition from a disk
/// image or accessing a specific region of a file.
///
/// # Example
///
/// ```rust,ignore
/// use seance_core::data_source::{FileDataSource, WindowSource};
/// use std::sync::Arc;
///
/// let disk = Arc::new(FileDataSource::new("disk.dd".into())?);
///
/// // Create a view of the first partition (starting at offset 1048576, 500MB)
/// let partition = WindowSource::new(disk, 1048576, 500 * 1024 * 1024);
/// ```
#[derive(Debug)]
pub struct WindowSource {
    pub inner: Arc<dyn DataSource>,
    pub start_offset: u64,
    pub length: u64,
}

impl WindowSource {
    pub fn new(inner: Arc<dyn DataSource>, start_offset: u64, length: u64) -> Self {
        Self {
            inner,
            start_offset,
            length,
        }
    }
}

impl DataSource for WindowSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.length {
            return Ok(0);
        }
        let remaining = self.length - offset;
        let to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
        let buf = &mut buf[..to_read];

        // Fail closed on a wrapping physical address: a corrupt window whose
        // start_offset is near u64::MAX must never wrap to a near-zero read and
        // silently serve the wrong bytes.
        let phys = self.start_offset.checked_add(offset).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "WindowSource physical offset overflowed u64",
            )
        })?;
        self.inner.read_at(phys, buf)
    }

    fn size(&self) -> u64 {
        self.length
    }

    fn physical_map(&self, offset: u64, len: u64) -> PhysicalMap {
        if offset >= self.length {
            return PhysicalMap::empty(ExtentPrecision::Exact);
        }
        let len = len.min(self.length - offset);
        let Some(phys) = self.start_offset.checked_add(offset) else {
            // Overflowing window: no single device range can be named for it.
            return PhysicalMap::empty(ExtentPrecision::Synthetic);
        };
        self.inner.physical_map(phys, len)
    }
}

/// A [`DataSource`] that maps non-contiguous physical runs to a contiguous logical view.
///
/// This is essential for file system parsing where file data is fragmented across
/// multiple physical locations (NTFS data runs, ext4 extents).
///
/// # Run Format
///
/// Each run is a tuple of `(Option<physical_offset>, length)`:
/// - `Some(offset)` - Data at the physical offset in the underlying source
/// - `None` - Sparse/unallocated region, reads return zeros
///
/// # Example
///
/// ```rust,ignore
/// use seance_core::data_source::{FileDataSource, RunListDataSource};
/// use std::sync::Arc;
///
/// let disk = Arc::new(FileDataSource::new("disk.dd".into())?);
///
/// // File with 3 fragments:
/// // - First 4KB at physical offset 1000
/// // - Sparse hole of 4KB (zeros)
/// // - Second 8KB at physical offset 50000
/// let runs = vec![
///     (Some(1000), 4096),
///     (None, 4096),        // Sparse run
///     (Some(50000), 8192),
/// ];
/// let file_data = RunListDataSource::from_allocation(disk, runs);
///
/// // Reads present a unified 16KB view
/// assert_eq!(file_data.size(), 16384);
/// ```
/// Cap on the number of data runs serialized into artifact metadata, bounding
/// row size for very fragmented files. The completeness flag reports truncation.
pub const MAX_METADATA_DATA_RUNS: usize = 4096;

/// Coalesce adjacent contiguous byte runs and serialize them to the `data_runs`
/// metadata format the API content resolver reads back: a JSON array of
/// `[byte_offset | null, byte_length]` pairs, where a `null` offset is a sparse
/// (zero-filled) run. Offsets are relative to the filesystem-window data source.
/// Returns the JSON value plus a completeness flag (`false` if the cap truncated
/// the list, meaning re-served content would be short).
pub fn byte_runs_to_metadata(runs: &[(Option<u64>, u64)]) -> (serde_json::Value, bool) {
    let mut coalesced: Vec<(Option<u64>, u64)> = Vec::new();
    for &(offset, len) in runs {
        if len == 0 {
            continue;
        }
        if let Some(last) = coalesced.last_mut() {
            let contiguous = match (last.0, offset) {
                // checked_add: a wrapping end offset must not be read as adjacent
                // to the next run and wrongly coalesced (BUG-128).
                (Some(last_off), Some(off)) => last_off.checked_add(last.1) == Some(off),
                (None, None) => true,
                _ => false,
            };
            if contiguous {
                if let Some(merged) = last.1.checked_add(len) {
                    last.1 = merged;
                    continue;
                }
                // Merged length would overflow u64: keep the runs separate
                // rather than wrap to a small, wrong length.
            }
        }
        coalesced.push((offset, len));
    }
    let complete = coalesced.len() <= MAX_METADATA_DATA_RUNS;
    coalesced.truncate(MAX_METADATA_DATA_RUNS);
    let arr: Vec<serde_json::Value> = coalesced
        .iter()
        .map(|&(o, l)| serde_json::json!([o, l]))
        .collect();
    (serde_json::json!(arr), complete)
}

/// Cut or pad `runs` so they describe exactly `logical_size` bytes.
///
/// Longer than logical: trim, dropping cluster slack. Shorter: append one
/// sparse run so a trailing unallocated hole reads as zeros to the file's full
/// length rather than ending the read early.
///
/// Exposed so a caller holding runs it must persist (rather than a source) can
/// apply the same reduction, and so the rule lives in one place.
pub fn fit_runs_to_logical(
    runs: Vec<(Option<u64>, u64)>,
    logical_size: u64,
) -> Vec<(Option<u64>, u64)> {
    // Saturating, for the same reason `from_allocation` saturates: a corrupt
    // run list summing past u64::MAX must not fold to a small total and turn
    // this into a multi-exabyte sparse pad (BUG-093).
    let allocated = runs
        .iter()
        .fold(0u64, |acc, (_, len)| acc.saturating_add(*len));

    if allocated == logical_size {
        return runs;
    }
    if allocated < logical_size {
        let mut runs = runs;
        runs.push((None, logical_size - allocated));
        return runs;
    }

    // Allocated exceeds logical: keep runs until the logical end, cutting the
    // one that straddles it. A run cut to zero length is dropped rather than
    // kept as an empty entry, so the cumulative table stays strictly
    // increasing and binary search cannot land on a zero-width run.
    let mut kept = Vec::with_capacity(runs.len());
    let mut covered = 0u64;
    for (start, len) in runs {
        if covered >= logical_size {
            break;
        }
        let remaining = logical_size - covered;
        let take = len.min(remaining);
        if take > 0 {
            kept.push((start, take));
            covered += take;
        }
    }
    kept
}

#[derive(Debug)]
pub struct RunListDataSource {
    pub inner: Arc<dyn DataSource>,
    /// List of (start_offset_in_inner, length_in_bytes)
    /// If start_offset_in_inner is None, it represents a sparse/zero-filled hole.
    pub runs: Vec<(Option<u64>, u64)>,
    /// Cumulative offsets for binary search: cumulative_offsets[i] = sum of run lengths [0..i]
    cumulative_offsets: Vec<u64>,
    pub total_size: u64,
}

impl RunListDataSource {
    /// A source whose content **is** the allocation the runs describe.
    ///
    /// Correct for a region that has no logical length of its own — a
    /// partition window, a device extent, a raw span of clusters being carved.
    /// For a *file* it is almost always wrong: a run list allocates whole
    /// clusters, and the bytes past the file's logical end are slack belonging
    /// to whatever occupied those clusters before.
    ///
    /// Use [`Self::with_logical_size`] whenever the filesystem states a length.
    /// The name is deliberate: this constructor asserts that the allocation is
    /// the content, and that claim should be made on purpose rather than by
    /// reaching for a function called `new`.
    pub fn from_allocation(inner: Arc<dyn DataSource>, runs: Vec<(Option<u64>, u64)>) -> Self {
        // Saturate rather than wrap: a corrupt run list whose lengths sum past
        // u64::MAX must not fold to a tiny total_size and mis-map find_run onto
        // the wrong physical bytes (BUG-093). Saturating keeps the cumulative
        // table monotonic so binary search stays correct.
        let total_size = runs
            .iter()
            .fold(0u64, |acc, (_, len)| acc.saturating_add(*len));

        // Build cumulative offset table for O(log n) binary search
        let mut cumulative_offsets = Vec::with_capacity(runs.len());
        let mut cumulative = 0u64;
        for (_, len) in &runs {
            cumulative_offsets.push(cumulative);
            cumulative = cumulative.saturating_add(*len);
        }

        Self {
            inner,
            runs,
            cumulative_offsets,
            total_size,
        }
    }

    /// A source of exactly `logical_size` bytes, backed by `runs`.
    ///
    /// This is what a **file** wants. A run list allocates whole clusters, so
    /// its total is the allocated size; the logical size is what the filesystem
    /// says the file contains. The two differ whenever the last cluster is
    /// partly slack, which is almost always.
    ///
    /// Serving the allocation instead means the trailing slack — bytes from
    /// whatever previously occupied those clusters — is delivered as file
    /// content. It reaches a hex view, a download, an export, and a re-hash:
    /// the digest is then taken over file-plus-slack and matches no hash any
    /// other tool computes, so a hash-set lookup misses and a report states a
    /// figure nothing reproduces. That is the defect this constructor exists to
    /// make unavailable by accident (B2-064).
    ///
    /// Both directions are handled:
    ///
    /// * allocation **longer** than logical — trim, dropping the slack;
    /// * allocation **shorter** — append one sparse run, so a file with a
    ///   trailing unallocated hole reads to its full length as zeros rather
    ///   than stopping early, matching TSK and Autopsy (BUG-154).
    ///
    /// A caller reading a region with no logical length of its own wants
    /// [`Self::from_allocation`].
    pub fn with_logical_size(
        inner: Arc<dyn DataSource>,
        runs: Vec<(Option<u64>, u64)>,
        logical_size: u64,
    ) -> Self {
        Self::from_allocation(inner, fit_runs_to_logical(runs, logical_size))
    }

    /// Find the run index containing the given offset using binary search
    /// Returns (run_index, offset_within_run)
    fn find_run(&self, offset: u64) -> Option<(usize, u64)> {
        if offset >= self.total_size {
            return None;
        }

        // Binary search to find the run containing this offset
        match self.cumulative_offsets.binary_search(&offset) {
            Ok(idx) => Some((idx, 0)), // Exact match at run boundary
            Err(idx) => {
                if idx == 0 {
                    None // Offset is before first run
                } else {
                    let run_idx = idx - 1;
                    let offset_in_run = offset - self.cumulative_offsets[run_idx];
                    Some((run_idx, offset_in_run))
                }
            }
        }
    }
}

impl DataSource for RunListDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.total_size {
            return Ok(0);
        }

        let mut bytes_read = 0;
        let mut buf_offset = 0;

        // Find the starting run using binary search - O(log n) instead of O(n)
        let (mut run_idx, mut offset_in_run) = match self.find_run(offset) {
            Some(result) => result,
            None => return Ok(0),
        };

        // Read from consecutive runs until buffer is full
        while buf_offset < buf.len() && run_idx < self.runs.len() {
            let (run_start, run_len) = &self.runs[run_idx];

            // How many bytes can we read from this run?
            let remaining_in_run = run_len - offset_in_run;
            let remaining_in_buf = buf.len() - buf_offset;
            let to_read = std::cmp::min(remaining_in_run, remaining_in_buf as u64) as usize;

            let target_buf = &mut buf[buf_offset..buf_offset + to_read];

            match run_start {
                Some(physical_start) => {
                    // Read from physical source. Fail closed if a corrupt run's
                    // physical_start wraps u64 when the in-run offset is added --
                    // a wrapped address would silently read unrelated bytes.
                    let phys = physical_start.checked_add(offset_in_run).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "run-list physical offset overflowed u64",
                        )
                    })?;
                    let read = self.inner.read_at(phys, target_buf)?;
                    if read < to_read {
                        // Short read from the inner source: only count bytes that
                        // were actually written — never stale buffer contents.
                        return Ok(bytes_read + read);
                    }
                }
                None => {
                    // Sparse run: fill with zeros
                    target_buf.fill(0);
                }
            }

            bytes_read += to_read;
            buf_offset += to_read;

            // Move to next run
            run_idx += 1;
            offset_in_run = 0; // Subsequent runs start from beginning
        }

        Ok(bytes_read)
    }

    fn size(&self) -> u64 {
        self.total_size
    }

    fn physical_map(&self, offset: u64, len: u64) -> PhysicalMap {
        let mut accumulated = PhysicalMap::empty(ExtentPrecision::Exact);
        let end = offset.saturating_add(len).min(self.total_size);
        let mut pos = offset;

        let Some((mut run_idx, mut off_in_run)) = self.find_run(pos) else {
            return accumulated;
        };

        while pos < end && run_idx < self.runs.len() {
            let (run_start, run_len) = self.runs[run_idx];
            let take = (run_len - off_in_run).min(end - pos);
            match run_start {
                Some(phys) => match phys.checked_add(off_in_run) {
                    // Recurse: this piece lives at `phys + off_in_run` in the
                    // inner source, which may itself split it across fragments.
                    Some(inner_off) => {
                        let sub = self.inner.physical_map(inner_off, take);
                        // `absorb` rather than `extend`: an inner map's auxiliary source
                        // indices are meaningful only against its own table.
                        accumulated.absorb(sub);
                    }
                    // Corrupt run whose physical offset wraps u64: we cannot name
                    // a device location for this piece (BUG-094). Content reads at
                    // the same offset already fail closed; degrade the advisory
                    // map rather than point at the wrong disk offset.
                    None => {
                        accumulated.precision =
                            accumulated.precision.worst(ExtentPrecision::Synthetic);
                        accumulated.extents.push(PhysicalExtent::hole(take));
                    }
                },
                None => {
                    // Sparse hole: zero-filled, no device backing. This is exact
                    // knowledge (there are no on-disk bytes), so precision holds.
                    accumulated.extents.push(PhysicalExtent::hole(take));
                }
            }
            pos += take;
            run_idx += 1;
            off_in_run = 0;
        }

        accumulated
    }
}

/// Adapter that provides [`Read`] + [`Seek`] access to a [`DataSource`].
///
/// Most Rust parsing libraries expect `Read` or `Read + Seek` traits. This adapter
/// wraps a stateless `DataSource` with a position cursor to satisfy those APIs.
///
/// # Example
///
/// ```rust,ignore
/// use seance_core::data_source::{FileDataSource, SourceCursor};
/// use std::io::{Read, Seek, SeekFrom};
/// use std::sync::Arc;
///
/// let source = Arc::new(FileDataSource::new("file.bin".into())?);
/// let mut cursor = SourceCursor::new(source);
///
/// // Sequential reading
/// let mut header = [0u8; 4];
/// cursor.read_exact(&mut header)?;
///
/// // Seeking
/// cursor.seek(SeekFrom::Start(100))?;
/// cursor.read_exact(&mut header)?;
/// ```
///
/// # Note
///
/// `SourceCursor` is read-only. The [`Write`] trait is implemented but returns
/// an error if called, as some libraries require `Write` even for read operations.
#[derive(Clone)]
pub struct SourceCursor {
    inner: Arc<dyn DataSource>,
    position: u64,
}

impl SourceCursor {
    pub fn new(inner: Arc<dyn DataSource>) -> Self {
        Self { inner, position: 0 }
    }
}

impl Debug for SourceCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceCursor")
            .field("inner", &self.inner)
            .field("position", &self.position)
            .finish()
    }
}

impl Read for SourceCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes_read = self.inner.read_at(self.position, buf)?;
        self.position += bytes_read as u64;
        Ok(bytes_read)
    }
}

impl Seek for SourceCursor {
    /// Seek within the underlying source.
    ///
    /// The target is computed in `i128` so no legal `u64` offset can be
    /// misread. Doing this in `i64` (as this once did) reinterpreted any offset
    /// above `i64::MAX` as negative, so `SeekFrom::End(0)` on a very large
    /// source — and every `SeekFrom::Start` past 8 EiB — was rejected as a
    /// "negative position", and `size + p` could overflow outright. A parser
    /// handed that error reports the evidence as unreadable rather than reading
    /// it (B3-008 family).
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let size = self.inner.size();
        let new_pos: i128 = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(p) => size as i128 + p as i128,
            SeekFrom::Current(p) => self.position as i128 + p as i128,
        };

        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid seek to negative position",
            ));
        }

        // Past u64::MAX there is no address to read from; say so rather than
        // truncate to some other, wrong offset.
        self.position = u64::try_from(new_pos).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid seek past the end of the u64 address space",
            )
        })?;
        Ok(self.position)
    }
}

impl Write for SourceCursor {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        // SourceCursor is read-only, but some libraries (like GPT) require Write trait
        // even for read-only operations. Return error if actually called.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SourceCursor is read-only",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        // No-op for read-only cursor
        Ok(())
    }
}

/// A caching wrapper that reduces redundant reads from the underlying [`DataSource`].
///
/// Particularly useful for compressed containers (E01, VMDK) where adjacent reads
/// may trigger the same expensive decompression operation. The cache stores a
/// window of recently read data to serve overlapping requests efficiently.
///
/// # Buffer Size
///
/// - Default: 256KB (good balance for forensic workloads)
/// - Use larger buffers for highly compressed data with expensive decompression
/// - Use smaller buffers when memory is constrained
///
/// # Example
///
/// ```rust,ignore
/// use seance_core::data_source::{FileDataSource, BufferedDataSource};
/// use std::sync::Arc;
///
/// let raw = Arc::new(FileDataSource::new("compressed.e01".into())?);
///
/// // Wrap with default 256KB buffer
/// let buffered = Arc::new(BufferedDataSource::with_default_buffer(raw));
///
/// // Or with custom buffer size (1MB for heavy compression)
/// let buffered = Arc::new(BufferedDataSource::new(raw, 1024 * 1024));
/// ```
#[derive(Debug)]
pub struct BufferedDataSource {
    inner: Arc<dyn DataSource>,
    cache: Mutex<BufferCache>,
}

#[derive(Debug)]
struct BufferCache {
    /// Cached data block
    data: Vec<u8>,
    /// Offset in the underlying source where this cache starts
    offset: u64,
    /// Size of the buffer (typically 64KB - 1MB)
    buffer_size: usize,
}

impl BufferedDataSource {
    /// Create a new buffered data source with the specified buffer size
    pub fn new(inner: Arc<dyn DataSource>, buffer_size: usize) -> Self {
        Self {
            inner,
            cache: Mutex::new(BufferCache {
                data: Vec::new(),
                offset: 0,
                buffer_size,
            }),
        }
    }

    /// Create with default 256KB buffer (good balance for forensic workloads)
    pub fn with_default_buffer(inner: Arc<dyn DataSource>) -> Self {
        Self::new(inner, 256 * 1024)
    }
}

impl DataSource for BufferedDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| io::Error::other("Cache mutex poisoned"))?;

        // Check if requested data is in cache
        // saturating_add: a cached window ending past u64::MAX must not wrap to
        // a small end offset and make every later read look like a cache miss
        // (or, worse, a hit at the wrong bytes).
        let cache_end = cache.offset.saturating_add(cache.data.len() as u64);

        if !cache.data.is_empty() && offset >= cache.offset && offset < cache_end {
            // Partial or full cache hit
            let offset_in_cache = (offset - cache.offset) as usize;
            let available = cache.data.len() - offset_in_cache;
            let to_copy = std::cmp::min(available, buf.len());

            buf[..to_copy].copy_from_slice(&cache.data[offset_in_cache..offset_in_cache + to_copy]);

            // If we satisfied the entire request, return
            if to_copy == buf.len() {
                return Ok(to_copy);
            }

            // Otherwise, fall through to refill cache for remaining data
        }

        // Cache miss or incomplete - refill cache starting at requested offset
        let read_size = std::cmp::max(buf.len(), cache.buffer_size);
        // Drop the old window first: if the refill fails, the zero-extended and
        // possibly part-overwritten buffer must not be served as a cache hit
        // for the previous offset.
        cache.data.clear();
        cache.data.resize(read_size, 0);

        let bytes_read = match self.inner.read_at(offset, &mut cache.data) {
            Ok(n) => n,
            Err(e) => {
                cache.data.clear();
                return Err(e);
            }
        };
        cache.data.truncate(bytes_read);
        cache.offset = offset;

        // Copy to output buffer
        let to_copy = std::cmp::min(bytes_read, buf.len());
        buf[..to_copy].copy_from_slice(&cache.data[..to_copy]);

        Ok(to_copy)
    }

    fn size(&self) -> u64 {
        self.inner.size()
    }

    fn get_underlying_path(&self) -> Option<PathBuf> {
        self.inner.get_underlying_path()
    }

    fn supports_siblings(&self) -> bool {
        self.inner.supports_siblings()
    }

    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        self.inner.open_sibling(suffix)
    }

    fn open_relative(&self, relative: &str) -> Option<Arc<dyn DataSource>> {
        self.inner.open_relative(relative)
    }

    fn relative_withheld(&self, relative: &str) -> bool {
        self.inner.relative_withheld(relative)
    }

    fn supports_ancestors(&self) -> bool {
        self.inner.supports_ancestors()
    }

    fn open_from_ancestor(&self, levels: usize, relative: &str) -> Option<Arc<dyn DataSource>> {
        self.inner.open_from_ancestor(levels, relative)
    }

    fn list_from_ancestor(&self, levels: usize, relative_dir: &str) -> Option<Vec<String>> {
        self.inner.list_from_ancestor(levels, relative_dir)
    }

    fn physical_map(&self, offset: u64, len: u64) -> PhysicalMap {
        // Transparent 1:1 cache: same coordinate space as the inner source.
        self.inner.physical_map(offset, len)
    }
}

/// A [`DataSource`] wrapper that caches fixed-size, chunk-aligned regions of the
/// inner source in an LRU. Forensic parsers issue many small, localized reads
/// (MFT records, inode tables, directory blocks); without a cache each is a
/// fresh read of the inner source. This matters most for E01/EWF images, where
/// every inner read is an isolated-helper IPC round-trip (or a libewf call that
/// re-decompresses the whole containing chunk) -- reading 1 KiB at a time across
/// a 64 KiB chunk would otherwise decode that chunk ~64 times. Caching decoded
/// chunks turns those into memory copies.
///
/// Unlike [`BufferedDataSource`] (a single sliding window, good only for
/// sequential access) this keeps the N most-recently-used chunks, so random
/// access across a working set stays cached.
pub struct CachingDataSource {
    inner: Arc<dyn DataSource>,
    chunk_size: u64,
    size: u64,
    cache: Mutex<LruCache<u64, Arc<Vec<u8>>>>,
}

impl Debug for CachingDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingDataSource")
            .field("chunk_size", &self.chunk_size)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl CachingDataSource {
    /// Wrap `inner`, caching up to `max_bytes` of it in `chunk_size`-aligned
    /// chunks. Both are floored to at least one chunk.
    pub fn new(inner: Arc<dyn DataSource>, chunk_size: usize, max_bytes: usize) -> Self {
        let chunk_size = chunk_size.max(1) as u64;
        let size = inner.size();
        let max_chunks = (max_bytes / chunk_size as usize).max(1);
        Self {
            inner,
            chunk_size,
            size,
            // max_chunks >= 1, so the NonZeroUsize is always valid.
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(max_chunks).unwrap())),
        }
    }

    /// Wrap with defaults tuned for evidence images: 64 KiB chunks, 128 MiB cache.
    pub fn with_defaults(inner: Arc<dyn DataSource>) -> Self {
        Self::new(inner, 64 * 1024, 128 * 1024 * 1024)
    }

    /// Return chunk `index`, from the cache or by reading it from `inner`. The
    /// inner read happens without the cache lock held so concurrent readers of
    /// other chunks aren't blocked; a concurrent miss on the same chunk just
    /// reads twice (rare, and correct).
    fn chunk(&self, index: u64) -> io::Result<Arc<Vec<u8>>> {
        if let Some(hit) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&index)
            .cloned()
        {
            return Ok(hit);
        }

        let start = index * self.chunk_size;
        if start >= self.size {
            return Ok(Arc::new(Vec::new()));
        }
        let want = self.chunk_size.min(self.size - start) as usize;
        let mut data = vec![0u8; want];
        let mut off = 0usize;
        while off < want {
            match self.inner.read_at(start + off as u64, &mut data[off..])? {
                0 => break,
                n => off += n,
            }
        }
        let short = off < want;
        data.truncate(off);

        let arc = Arc::new(data);
        // Memoize only a chunk the inner source delivered in FULL. A short fill
        // is the inner source failing to supply bytes it claims to have (a
        // truncated container, an IPC round-trip that returned early, an extent
        // that ran out). Caching it makes that momentary shortfall the permanent
        // view of this range: every later read, hash and preview of the region
        // is served the short prefix as though it were the whole content, with
        // nothing to say the bytes were never obtained. Not caching it costs one
        // re-read and keeps the next attempt honest.
        if short {
            warn!(
                "CachingDataSource: chunk {} at offset {} delivered {} of {} bytes; \
                 not caching a short fill",
                index,
                start,
                arc.len(),
                want
            );
        } else {
            self.cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .put(index, arc.clone());
        }
        Ok(arc)
    }
}

impl DataSource for CachingDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.size || buf.is_empty() {
            return Ok(0);
        }
        // saturating_add: a request whose end offset passes u64::MAX must clamp
        // to the source size, never wrap to an end below `offset` (which would
        // return 0 bytes read as if the source were exhausted).
        let end = offset.saturating_add(buf.len() as u64).min(self.size);
        let mut pos = offset;
        let mut written = 0usize;
        while pos < end {
            let index = pos / self.chunk_size;
            let chunk_start = index * self.chunk_size;
            let chunk = self.chunk(index)?;
            let within = (pos - chunk_start) as usize;
            if within >= chunk.len() {
                // Inner returned a short chunk (unexpected EOF); stop here.
                break;
            }
            let n = (chunk.len() - within).min((end - pos) as usize);
            buf[written..written + n].copy_from_slice(&chunk[within..within + n]);
            written += n;
            pos += n as u64;
        }
        Ok(written)
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn get_underlying_path(&self) -> Option<PathBuf> {
        self.inner.get_underlying_path()
    }

    fn supports_siblings(&self) -> bool {
        self.inner.supports_siblings()
    }

    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        self.inner.open_sibling(suffix)
    }

    fn open_relative(&self, relative: &str) -> Option<Arc<dyn DataSource>> {
        self.inner.open_relative(relative)
    }

    fn relative_withheld(&self, relative: &str) -> bool {
        self.inner.relative_withheld(relative)
    }

    fn supports_ancestors(&self) -> bool {
        self.inner.supports_ancestors()
    }

    fn open_from_ancestor(&self, levels: usize, relative: &str) -> Option<Arc<dyn DataSource>> {
        self.inner.open_from_ancestor(levels, relative)
    }

    fn list_from_ancestor(&self, levels: usize, relative_dir: &str) -> Option<Vec<String>> {
        self.inner.list_from_ancestor(levels, relative_dir)
    }

    fn physical_map(&self, offset: u64, len: u64) -> PhysicalMap {
        // Transparent 1:1 LRU cache: same coordinate space as the inner source.
        self.inner.physical_map(offset, len)
    }
}

/// A [`DataSource`] backed by an in-memory byte slice.
///
/// Used for small data that is already loaded into memory, such as
/// resident NTFS attributes or extracted embedded content.
#[derive(Debug, Clone)]
pub struct ByteSliceDataSource {
    data: Vec<u8>,
}

impl ByteSliceDataSource {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl DataSource for ByteSliceDataSource {
    fn resident_bytes(&self) -> Option<&[u8]> {
        Some(&self.data)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return Ok(0);
        }
        let to_read = std::cmp::min(buf.len(), self.data.len() - offset);
        buf[..to_read].copy_from_slice(&self.data[offset..offset + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
    // physical_map: inherits the default (opaque/Synthetic). In-memory bytes
    // (NTFS resident data, a decompressed file, a materialized ZIP entry) have
    // no single device byte range, which the default honestly reports.
}

/// Marks a decoded container image (E01/VHD/VMDK/QCOW2/AFF4) as the backing
/// device for physical-location purposes.
///
/// Reads pass straight through; [`DataSource::physical_map`] treats this
/// source's own offset as the device-image coordinate and reports it as exact.
/// The container's on-file compression is transparent here because the decoded
/// image reproduces the original disk byte-for-byte, so an offset into the
/// decoded image *is* the physical offset on the acquired disk.
#[derive(Debug)]
pub struct DeviceImageSource {
    pub inner: Arc<dyn DataSource>,
}

impl DeviceImageSource {
    pub fn new(inner: Arc<dyn DataSource>) -> Self {
        Self { inner }
    }
}

impl DataSource for DeviceImageSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_at(offset, buf)
    }

    fn size(&self) -> u64 {
        self.inner.size()
    }

    fn get_underlying_path(&self) -> Option<PathBuf> {
        self.inner.get_underlying_path()
    }

    fn supports_siblings(&self) -> bool {
        self.inner.supports_siblings()
    }

    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        self.inner.open_sibling(suffix)
    }

    fn open_relative(&self, relative: &str) -> Option<Arc<dyn DataSource>> {
        self.inner.open_relative(relative)
    }

    fn relative_withheld(&self, relative: &str) -> bool {
        self.inner.relative_withheld(relative)
    }

    fn supports_ancestors(&self) -> bool {
        self.inner.supports_ancestors()
    }

    fn open_from_ancestor(&self, levels: usize, relative: &str) -> Option<Arc<dyn DataSource>> {
        self.inner.open_from_ancestor(levels, relative)
    }

    fn list_from_ancestor(&self, levels: usize, relative_dir: &str) -> Option<Vec<String>> {
        self.inner.list_from_ancestor(levels, relative_dir)
    }

    fn physical_map(&self, offset: u64, len: u64) -> PhysicalMap {
        let avail = self.size().saturating_sub(offset);
        PhysicalMap::exact(offset, len.min(avail))
    }
}

/// Wraps an inner [`DataSource`] and answers [`DataSource::open_sibling`] from a
/// pre-resolved map of `suffix -> sibling source`, and
/// [`DataSource::open_relative`] from a pre-resolved map of `name -> neighbour`.
/// Every other call delegates to `inner`.
///
/// This exists so a filesystem parser that already has a directory listing in
/// hand can attach a hive's `.LOG1`/`.LOG2` transaction logs (or a database's
/// `-wal`) to the file's data source, letting a downstream plugin reach those
/// siblings via the existing `open_sibling` contract even when the evidence is a
/// disk image (whose synthetic filesystem sources have no path-based sibling
/// lookup of their own). The name-keyed map does the same for a neighbour that
/// is not a suffix of this file's name — a Chrome block file's `data_2` beside
/// its `data_1` (HUNT-184). Reads, size, underlying path, and physical mapping
/// are all forwarded unchanged, so wrapping is transparent to every other
/// consumer.
///
/// [`DataSource::supports_siblings`] is `true` when anything was bundled: the
/// bundle was built from the listing the neighbours were looked for in, so "not
/// in the bundle" is "looked, and it is not there", not "could not look"
/// (HUNT-101). An empty bundle answers for its inner source.
#[derive(Debug)]
pub struct SiblingBundleSource {
    inner: Arc<dyn DataSource>,
    /// Map from the exact suffix requested (e.g. `".LOG1"`) to that sibling's
    /// source. Lookups are exact-match on the suffix string.
    siblings: HashMap<String, Arc<dyn DataSource>>,
    /// Map from a neighbour's file name, lower-cased (e.g. `"data_2"`), to its
    /// source. Lookups are case-insensitive, since FAT stores `DATA_2`.
    relatives: HashMap<String, Arc<dyn DataSource>>,
    /// Lower-cased neighbour names present in the directory but withheld
    /// because the name occurs more than once there (HUNT-195).
    withheld: std::collections::HashSet<String>,
}

impl SiblingBundleSource {
    /// Wrap `inner`, attaching the given `suffix -> source` siblings. The suffix
    /// keys must match exactly what a consumer passes to `open_sibling`.
    pub fn new(inner: Arc<dyn DataSource>, siblings: HashMap<String, Arc<dyn DataSource>>) -> Self {
        Self {
            inner,
            siblings,
            relatives: HashMap::new(),
            withheld: std::collections::HashSet::new(),
        }
    }

    /// Also attach `name -> source` neighbours, answered by `open_relative`
    /// for a bare file name in the same directory. Names are matched
    /// case-insensitively.
    pub fn with_relatives(mut self, relatives: HashMap<String, Arc<dyn DataSource>>) -> Self {
        self.relatives = relatives
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        self
    }

    /// Also record neighbour names that were present in the directory but
    /// withheld (a name occurring twice is not chosen between), so
    /// `relative_withheld` can say so. Names are matched case-insensitively.
    pub fn with_withheld<I: IntoIterator<Item = String>>(mut self, names: I) -> Self {
        self.withheld = names.into_iter().map(|n| n.to_ascii_lowercase()).collect();
        self
    }
}

impl DataSource for SiblingBundleSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_at(offset, buf)
    }

    fn size(&self) -> u64 {
        self.inner.size()
    }

    fn get_underlying_path(&self) -> Option<PathBuf> {
        self.inner.get_underlying_path()
    }

    fn supports_siblings(&self) -> bool {
        !self.siblings.is_empty() || !self.relatives.is_empty() || self.inner.supports_siblings()
    }

    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        // Prefer an explicitly attached sibling; fall back to the inner source's
        // own notion of siblings (e.g. a file-backed inner still resolves by path).
        self.siblings
            .get(suffix)
            .cloned()
            .or_else(|| self.inner.open_sibling(suffix))
    }

    fn open_relative(&self, relative: &str) -> Option<Arc<dyn DataSource>> {
        self.relatives
            .get(&relative.to_ascii_lowercase())
            .cloned()
            .or_else(|| self.inner.open_relative(relative))
    }

    fn relative_withheld(&self, relative: &str) -> bool {
        self.withheld.contains(&relative.to_ascii_lowercase())
            || self.inner.relative_withheld(relative)
    }

    fn supports_ancestors(&self) -> bool {
        self.inner.supports_ancestors()
    }

    fn open_from_ancestor(&self, levels: usize, relative: &str) -> Option<Arc<dyn DataSource>> {
        self.inner.open_from_ancestor(levels, relative)
    }

    fn list_from_ancestor(&self, levels: usize, relative_dir: &str) -> Option<Vec<String>> {
        self.inner.list_from_ancestor(levels, relative_dir)
    }

    fn physical_map(&self, offset: u64, len: u64) -> PhysicalMap {
        self.inner.physical_map(offset, len)
    }
}

/// Sidecar suffixes a filesystem parser bundles onto an emitted file so the
/// plugins that look for them can reach them inside a disk image.
///
/// `-wal` / `-journal` are SQLite's sidecars (`seance_sqlite_util::TempDb` and
/// the forensic SQLite parser ask for exactly these strings); `.LOG1` / `.LOG2`
/// / `.LOG` are the registry transaction logs `seance_plugin_registry`'s
/// `discover_logs` asks for. Lookups are exact-match, so the canonical spelling
/// used here is the one those consumers try first.
pub const BUNDLED_SIBLING_SUFFIXES: &[&str] = &["-wal", "-journal", ".LOG1", ".LOG2", ".LOG"];

/// A unified log tree as one filesystem walk listed it, shared by every
/// `.tracev3` of that walk (ROADMAP §1.6).
///
/// A `.tracev3` inside a disk image is served by a synthetic run-list source
/// with no path of its own, so the `uuidtext`, `dsc` and `timesync` files its
/// decode needs, which sit beside and above it, were unreachable and the record
/// said "tree not reachable". The walk that produced the entries already holds
/// the whole listing; this indexes the part of it a log tree lives in.
#[derive(Debug, Default)]
struct LogTreeIndex {
    /// Lower-cased full path to the file's source.
    files: HashMap<String, Arc<dyn DataSource>>,
    /// Lower-cased directory (no trailing slash) to the names directly in it,
    /// as listed (original case), sorted.
    dirs: HashMap<String, Vec<String>>,
}

/// A `.tracev3`'s source, answering [`DataSource::open_from_ancestor`] and
/// [`DataSource::list_from_ancestor`] from a [`LogTreeIndex`]. Everything else
/// is forwarded, so wrapping is transparent to every other consumer.
#[derive(Debug)]
struct LogTreeSource {
    inner: Arc<dyn DataSource>,
    own_path: String,
    index: Arc<LogTreeIndex>,
}

impl DataSource for LogTreeSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_at(offset, buf)
    }

    fn size(&self) -> u64 {
        self.inner.size()
    }

    fn get_underlying_path(&self) -> Option<PathBuf> {
        self.inner.get_underlying_path()
    }

    fn supports_siblings(&self) -> bool {
        self.inner.supports_siblings()
    }

    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        self.inner.open_sibling(suffix)
    }

    fn open_relative(&self, relative: &str) -> Option<Arc<dyn DataSource>> {
        self.inner.open_relative(relative)
    }

    fn relative_withheld(&self, relative: &str) -> bool {
        self.inner.relative_withheld(relative)
    }

    fn supports_ancestors(&self) -> bool {
        true
    }

    fn open_from_ancestor(&self, levels: usize, relative: &str) -> Option<Arc<dyn DataSource>> {
        if !relative_path_is_plain(relative) {
            return None;
        }
        let prefix = ancestor_prefix(&self.own_path, levels)?;
        self.index
            .files
            .get(&format!("{prefix}{relative}").to_ascii_lowercase())
            .cloned()
    }

    fn list_from_ancestor(&self, levels: usize, relative_dir: &str) -> Option<Vec<String>> {
        if !relative_dir.is_empty() && !relative_path_is_plain(relative_dir) {
            return None;
        }
        let prefix = ancestor_prefix(&self.own_path, levels)?;
        let dir = format!("{prefix}{relative_dir}").to_ascii_lowercase();
        let names = self.index.dirs.get(dir.trim_end_matches('/'))?;
        if names.len() > MAX_LISTED_NAMES {
            return None;
        }
        Some(names.clone())
    }

    fn physical_map(&self, offset: u64, len: u64) -> PhysicalMap {
        self.inner.physical_map(offset, len)
    }
}

/// Give every `.tracev3` in a filesystem walk's listing the reach of its own log
/// tree. Nothing is indexed unless the listing holds a `.tracev3`; only files
/// under a `uuidtext`, `diagnostics` or `.logarchive` directory are, so a walk of
/// millions of entries pays for the few thousand a log tree is made of. Deleted
/// files are never part of the tree: stale bytes from reallocated clusters would
/// be decoded as a format-string table that was never this machine's.
fn attach_unified_log_trees(entries: &mut [crate::artifact::Artifact]) {
    fn path_of(a: &crate::artifact::Artifact) -> Option<&str> {
        a.metadata
            .get("path")
            .or_else(|| a.metadata.get("name"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    }
    fn live_file(a: &crate::artifact::Artifact) -> bool {
        a.data.is_some()
            && a.metadata.get("is_directory").and_then(|v| v.as_bool()) != Some(true)
            && a.metadata.get("deleted").and_then(|v| v.as_bool()) != Some(true)
    }
    fn is_tracev3(path: &str) -> bool {
        path.len() > ".tracev3".len()
            && path.as_bytes()[path.len() - 8..].eq_ignore_ascii_case(b".tracev3")
    }

    let tracev3: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| live_file(e) && path_of(e).is_some_and(is_tracev3))
        .map(|(i, _)| i)
        .collect();
    if tracev3.is_empty() {
        return;
    }

    let mut index = LogTreeIndex::default();
    for entry in entries.iter().filter(|e| live_file(e)) {
        let (Some(path), Some(source)) = (path_of(entry), entry.data.as_ref()) else {
            continue;
        };
        let lower = path.to_ascii_lowercase();
        if !(lower.contains("/uuidtext/")
            || lower.contains("/diagnostics/")
            || lower.contains(".logarchive/"))
        {
            continue;
        }
        let Some((dir, name)) = path.rsplit_once('/') else {
            continue;
        };
        index
            .dirs
            .entry(dir.to_ascii_lowercase())
            .or_default()
            .push(name.to_string());
        index.files.insert(lower, source.clone());
    }
    for names in index.dirs.values_mut() {
        names.sort();
        names.dedup();
    }
    let index = Arc::new(index);
    for i in tracev3 {
        let own_path = path_of(&entries[i]).unwrap_or_default().to_string();
        if let Some(inner) = entries[i].data.take() {
            entries[i].data = Some(Arc::new(LogTreeSource {
                inner,
                own_path,
                index: index.clone(),
            }));
        }
    }
}

/// Attach in-image sidecars to the file entries a filesystem parser produced.
///
/// A hive or database inside a disk image is served by a synthetic run-list
/// source with no path of its own, so `open_sibling` has nothing to resolve
/// against and registry log replay / WAL-aware SQLite spills silently no-op —
/// while the same evidence loose on disk or inside a ZIP works. This walks the
/// emitted entries once, finds every `<file><suffix>` pair *within the same
/// listing*, and republishes the base file's source wrapped in a
/// [`SiblingBundleSource`] carrying its sidecars.
///
/// Matching is on the entry's `path` (falling back to `name`), case-insensitive
/// because `.LOG1` and `.log1` both occur. Entries flagged `deleted` are never
/// used as a sidecar: a sidecar recovered from reallocated clusters is stale
/// bytes, and handing SQLite a mismatched WAL can make it refuse the database
/// outright — losing content that parses fine today.
pub fn attach_sibling_bundles(entries: &mut [crate::artifact::Artifact]) {
    attach_unified_log_trees(entries);
    fn key(a: &crate::artifact::Artifact) -> Option<&str> {
        a.metadata
            .get("path")
            .or_else(|| a.metadata.get("name"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    }
    // A live file with content: the one predicate every pass uses, so a
    // deleted entry can be neither a sidecar nor the base a sidecar attaches to.
    fn usable(a: &crate::artifact::Artifact) -> bool {
        a.data.is_some()
            && a.metadata.get("is_directory").and_then(|v| v.as_bool()) != Some(true)
            && a.metadata.get("deleted").and_then(|v| v.as_bool()) != Some(true)
    }

    // Pass 1: the sidecars. Their base names are the only keys worth indexing,
    // so the map stays proportional to the sidecar count, not the file count.
    // A whole-image walk can emit millions of entries, so nothing is allocated
    // here for a file that is not a sidecar (and the neighbour passes below
    // allocate only for a file whose name they recognise).
    let mut sidecars: Vec<(String, &'static str, usize)> = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        if !usable(entry) {
            continue;
        }
        let Some(k) = key(entry) else { continue };
        let kb = k.as_bytes();
        for &suffix in BUNDLED_SIBLING_SUFFIXES {
            let sb = suffix.as_bytes();
            if kb.len() > sb.len() && kb[kb.len() - sb.len()..].eq_ignore_ascii_case(sb) {
                sidecars.push((k[..k.len() - sb.len()].to_ascii_lowercase(), suffix, i));
                break;
            }
        }
    }
    let mut block_groups = neighbour_groups(entries, chrome_block_file_name);
    block_groups.extend(neighbour_groups(entries, wbem_repository_file_name));
    if sidecars.is_empty() && block_groups.is_empty() {
        return;
    }

    // Pass 2: locate each sidecar's base file among the same entries.
    let wanted: std::collections::HashSet<&str> =
        sidecars.iter().map(|(base, _, _)| base.as_str()).collect();
    let mut base_index: HashMap<String, usize> = HashMap::new();
    for (i, entry) in entries.iter().enumerate() {
        if !usable(entry) {
            continue;
        }
        if let Some(k) = key(entry) {
            let lower = k.to_ascii_lowercase();
            if wanted.contains(lower.as_str()) {
                base_index.entry(lower).or_insert(i);
            }
        }
    }

    // Pass 3: group the sidecars per base, then rewrap that base's source once.
    let mut bundles: HashMap<usize, HashMap<String, Arc<dyn DataSource>>> = HashMap::new();
    for (base, suffix, sidecar_idx) in sidecars {
        let Some(&base_idx) = base_index.get(&base) else {
            continue;
        };
        if base_idx == sidecar_idx {
            continue;
        }
        let Some(source) = entries[sidecar_idx].data.clone() else {
            continue;
        };
        bundles
            .entry(base_idx)
            .or_default()
            .insert(suffix.to_string(), source);
    }

    // Pass 4: each Chrome block file reaches the others in its directory by
    // name (HUNT-184), and each WMI repository file its neighbours (HUNT-195).
    let mut relatives: HashMap<usize, HashMap<String, Arc<dyn DataSource>>> = HashMap::new();
    // A name the directory holds twice is withheld; the files that are
    // attached are told which, so "withheld" is not reported as "absent".
    let mut withheld: HashMap<usize, Vec<String>> = HashMap::new();
    for group in &block_groups {
        for &(i, _) in &group.members {
            if group.members.len() >= 2 {
                let neighbours: HashMap<String, Arc<dyn DataSource>> = group
                    .members
                    .iter()
                    .filter(|(j, _)| *j != i)
                    .filter_map(|(j, name)| Some((name.clone(), entries[*j].data.clone()?)))
                    .collect();
                relatives.insert(i, neighbours);
            }
            if !group.withheld.is_empty() {
                withheld.insert(i, group.withheld.clone());
            }
        }
    }

    let mut wrap: std::collections::BTreeSet<usize> = bundles.keys().copied().collect();
    wrap.extend(relatives.keys().copied());
    wrap.extend(withheld.keys().copied());
    for idx in wrap {
        let siblings = bundles.remove(&idx).unwrap_or_default();
        let neighbours = relatives.remove(&idx).unwrap_or_default();
        let held_back = withheld.remove(&idx).unwrap_or_default();
        if let Some(inner) = entries[idx].data.take() {
            entries[idx].data = Some(Arc::new(
                SiblingBundleSource::new(inner, siblings)
                    .with_relatives(neighbours)
                    .with_withheld(held_back),
            ) as Arc<dyn DataSource>);
        }
    }
}

/// Chrome's blockfile cache names its block files `data_0`, `data_1`, … (and
/// extension files `data_4` upward). `Some(lower-cased name)` for one.
fn chrome_block_file_name(path: &str) -> Option<String> {
    // Test on the borrowed name; allocate only for a match.
    let name = path.rsplit('/').next()?;
    let (prefix, digits) = name.as_bytes().split_at_checked(5)?;
    (prefix.eq_ignore_ascii_case(b"data_")
        && !digits.is_empty()
        && digits.len() <= 3
        && digits.iter().all(u8::is_ascii_digit))
    .then(|| name.to_ascii_lowercase())
}

/// A CIM (WMI) repository names its files `OBJECTS.DATA`, `INDEX.BTR` and
/// `MAPPING1/2/3.MAP` (Vista onward), with `MAPPING.VER`, `INDEX.MAP` and
/// `OBJECTS.MAP` on XP's `Repository/FS`. `Some(lower-cased name)` for one of
/// those in a `wbem/repository/` or `wbem/repository/fs/` directory — the
/// directory test keeps a stray `OBJECTS.DATA` elsewhere from being grouped.
fn wbem_repository_file_name(path: &str) -> Option<String> {
    const NAMES: &[&str] = &[
        "objects.data",
        "index.btr",
        "mapping1.map",
        "mapping2.map",
        "mapping3.map",
        "mapping.ver",
        "index.map",
        "objects.map",
    ];
    fn ends_with_ci(s: &str, suffix: &str) -> bool {
        s.len() >= suffix.len()
            && s.as_bytes()[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
    }
    // Test on the borrowed name and directory; allocate only for a match.
    let (dir, name) = path.rsplit_once('/')?;
    if !NAMES.iter().any(|n| n.eq_ignore_ascii_case(name)) {
        return None;
    }
    (ends_with_ci(dir, "/wbem/repository") || ends_with_ci(dir, "/wbem/repository/fs"))
        .then(|| name.to_ascii_lowercase())
}

/// One directory's neighbours: the files attached to each other, as
/// `(entry index, lower-cased name)`, and the names withheld because the
/// directory holds them more than once (HUNT-195).
struct NeighbourGroup {
    members: Vec<(usize, String)>,
    withheld: Vec<String>,
}

/// The files `name_of` recognises in each directory of the listing, as
/// `(entry index, lower-cased name)`, for directories holding two or more of
/// them (or one, beside a name withheld as duplicated) — Chrome block files (HUNT-184) and WMI repository files (HUNT-195).
/// Grouped on the entry's `path` only — an entry with no path cannot be placed
/// in a directory, and two profiles' caches both hold a `data_2`. Deleted
/// entries are skipped, as for the sidecars: stale block-file bytes read as a
/// live key would attribute some other URL to an entry, and a stale mapping
/// file would place the repository's pages wrongly.
fn neighbour_groups(
    entries: &[crate::artifact::Artifact],
    name_of: fn(&str) -> Option<String>,
) -> Vec<NeighbourGroup> {
    let mut by_dir: HashMap<String, Vec<(usize, String)>> = HashMap::new();
    for (i, entry) in entries.iter().enumerate() {
        if entry.data.is_none()
            || entry.metadata.get("is_directory").and_then(|v| v.as_bool()) == Some(true)
            || entry.metadata.get("deleted").and_then(|v| v.as_bool()) == Some(true)
        {
            continue;
        }
        let Some(path) = entry.metadata.get("path").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(name) = name_of(path) else {
            continue;
        };
        let dir = path[..path.len() - name.len()].to_ascii_lowercase();
        by_dir.entry(dir).or_default().push((i, name));
    }
    by_dir
        .into_values()
        .map(|group| {
            // One entry per name: two live `data_2` in one directory is not
            // something to choose between silently, so neither is attached.
            let count = |name: &str| group.iter().filter(|(_, n)| n == name).count();
            let members = group
                .iter()
                .filter(|(_, n)| count(n) == 1)
                .cloned()
                .collect::<Vec<_>>();
            let mut withheld: Vec<String> = group
                .iter()
                .filter(|(_, n)| count(n) > 1)
                .map(|(_, n)| n.clone())
                .collect();
            withheld.sort();
            withheld.dedup();
            NeighbourGroup { members, withheld }
        })
        .filter(|g| g.members.len() >= 2 || (!g.members.is_empty() && !g.withheld.is_empty()))
        .collect()
}

#[cfg(test)]
mod sibling_bundle_tests {
    use super::*;

    #[test]
    fn attached_sibling_is_reachable_via_open_sibling() {
        let hive: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"regf-hive".to_vec()));
        let log1: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"log1-bytes".to_vec()));

        let mut siblings = HashMap::new();
        siblings.insert(".LOG1".to_string(), log1);
        let bundled = SiblingBundleSource::new(hive, siblings);

        // The wrapped source reads exactly like its inner source.
        let mut buf = [0u8; 9];
        assert_eq!(bundled.read_at(0, &mut buf).unwrap(), 9);
        assert_eq!(&buf, b"regf-hive");
        assert_eq!(bundled.size(), 9);

        // The attached sibling is reachable through the standard contract.
        let sib = bundled
            .open_sibling(".LOG1")
            .expect("sibling should resolve");
        let mut sbuf = [0u8; 10];
        assert_eq!(sib.read_at(0, &mut sbuf).unwrap(), 10);
        assert_eq!(&sbuf, b"log1-bytes");

        // An unattached suffix falls through to the inner source (here: none).
        assert!(bundled.open_sibling(".LOG2").is_none());
    }

    // ── BUG-257: filesystem parsers must wire the wrapper up ────────────────

    mod bundle_wiring {
        use super::*;
        use crate::artifact::{Artifact, ArtifactType};
        use serde_json::json;
        use uuid::Uuid;

        fn entry(path: &str, bytes: &[u8], extra: serde_json::Value) -> Artifact {
            let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes.to_vec()));
            let mut md = json!({ "name": path.rsplit('/').next().unwrap(), "path": path });
            if let (Some(o), Some(e)) = (md.as_object_mut(), extra.as_object()) {
                for (k, v) in e {
                    o.insert(k.clone(), v.clone());
                }
            }
            Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, Some(ds), md)
        }

        fn sibling_bytes(a: &Artifact, suffix: &str) -> Option<Vec<u8>> {
            let sib = a.data.as_ref()?.open_sibling(suffix)?;
            let mut buf = vec![0u8; sib.size() as usize];
            sib.read_at(0, &mut buf).ok()?;
            Some(buf)
        }

        #[test]
        fn in_image_sidecars_become_reachable_siblings() {
            let mut entries = vec![
                entry("/Windows/System32/config/SYSTEM", b"regf", json!({})),
                entry("/Windows/System32/config/SYSTEM.LOG1", b"log1", json!({})),
                entry("/Windows/System32/config/SYSTEM.LOG2", b"log2", json!({})),
                entry("/data/app.db", b"SQLite", json!({})),
                entry("/data/app.db-wal", b"wal-frames", json!({})),
                entry("/data/unrelated.txt", b"hello", json!({})),
            ];
            attach_sibling_bundles(&mut entries);

            assert_eq!(
                sibling_bytes(&entries[0], ".LOG1").as_deref(),
                Some(&b"log1"[..])
            );
            assert_eq!(
                sibling_bytes(&entries[0], ".LOG2").as_deref(),
                Some(&b"log2"[..])
            );
            assert_eq!(
                sibling_bytes(&entries[3], "-wal").as_deref(),
                Some(&b"wal-frames"[..])
            );
            // The base file still reads exactly as before wrapping.
            let mut buf = [0u8; 4];
            entries[0]
                .data
                .as_ref()
                .unwrap()
                .read_at(0, &mut buf)
                .unwrap();
            assert_eq!(&buf, b"regf");
            // A file with no sidecar is untouched.
            assert!(entries[5]
                .data
                .as_ref()
                .unwrap()
                .open_sibling("-wal")
                .is_none());
        }

        /// HUNT-184. A Chrome blockfile cache inside a disk image: `data_1`'s
        /// long keys live in `data_2`/`data_3` beside it, which the cache
        /// parser opens by name through `open_relative`. Loose on disk that
        /// works through the file path; inside an image the synthetic source
        /// had no path, so every such key was `sibling_lookup_unsupported`.
        #[test]
        fn chrome_block_files_in_one_directory_reach_each_other_by_name() {
            let cache = "/Users/u/AppData/Local/Google/Chrome/User Data/Default/Cache";
            let mut entries = vec![
                entry(&format!("{cache}/data_0"), b"rankings", json!({})),
                entry(&format!("{cache}/data_1"), b"entries", json!({})),
                entry(&format!("{cache}/data_2"), b"one-k blocks", json!({})),
                entry(&format!("{cache}/DATA_3"), b"four-k blocks", json!({})),
                entry(
                    &format!("{cache}/data_4"),
                    b"stale",
                    json!({ "deleted": true }),
                ),
                entry(&format!("{cache}/index"), b"index", json!({})),
                entry(&format!("{cache}/f_000001"), b"external", json!({})),
                // Another profile's cache: never a sibling of the first.
                entry("/Other/Profile/Cache/data_2", b"another cache", json!({})),
            ];
            attach_sibling_bundles(&mut entries);

            let data_1 = entries[1].data.as_ref().unwrap();
            assert!(
                data_1.supports_siblings(),
                "a block file whose neighbours were bundled can look beside itself"
            );
            let read = |ds: Arc<dyn DataSource>| {
                let mut buf = vec![0u8; ds.size() as usize];
                ds.read_at(0, &mut buf).unwrap();
                buf
            };
            assert_eq!(
                read(
                    data_1
                        .open_relative("data_2")
                        .expect("data_2 beside data_1")
                ),
                b"one-k blocks"
            );
            assert_eq!(
                read(
                    data_1
                        .open_relative("data_3")
                        .expect("case-insensitive, as FAT")
                ),
                b"four-k blocks"
            );
            assert_eq!(read(data_1.open_relative("data_0").unwrap()), b"rankings");
            assert!(
                data_1.open_relative("data_4").is_none(),
                "a deleted block file is stale bytes and is not attached"
            );
            assert!(data_1.open_relative("index").is_none());
            assert!(data_1.open_relative("f_000001").is_none());
            // data_2 reaches data_1 the same way, and not the other profile's.
            let data_2 = entries[2].data.as_ref().unwrap();
            assert_eq!(read(data_2.open_relative("data_1").unwrap()), b"entries");
            // The lone block file in another directory has nothing bundled.
            assert!(!entries[7].data.as_ref().unwrap().supports_siblings());
            assert!(entries[7]
                .data
                .as_ref()
                .unwrap()
                .open_relative("data_1")
                .is_none());
            // The base file still reads as itself.
            assert_eq!(read(data_1.clone()), b"entries");
        }

        /// HUNT-195. A WMI repository inside a disk image: `OBJECTS.DATA` is
        /// only readable page-for-page through `MAPPING1/2/3.MAP` beside it,
        /// which the ASEP module opens by name through `open_relative`.
        #[test]
        fn wbem_repository_files_reach_each_other_by_name() {
            let repo = "/Windows/System32/wbem/Repository";
            let mut entries = vec![
                entry(&format!("{repo}/OBJECTS.DATA"), b"objects", json!({})),
                entry(&format!("{repo}/MAPPING1.MAP"), b"map one", json!({})),
                entry(&format!("{repo}/MAPPING2.MAP"), b"map two", json!({})),
                entry(&format!("{repo}/MAPPING3.MAP"), b"map three", json!({})),
                entry(&format!("{repo}/INDEX.BTR"), b"index", json!({})),
                entry(&format!("{repo}/unrelated.log"), b"log", json!({})),
                // A repository copy elsewhere is never a neighbour of the first.
                entry(
                    "/Windows.old/Windows/System32/wbem/Repository/MAPPING2.MAP",
                    b"another repository",
                    json!({}),
                ),
                // Not a repository directory: OBJECTS.DATA alone in a folder.
                entry("/Users/u/Desktop/OBJECTS.DATA", b"loose", json!({})),
                entry("/Users/u/Desktop/MAPPING1.MAP", b"loose map", json!({})),
            ];
            attach_sibling_bundles(&mut entries);
            let read = |ds: Arc<dyn DataSource>| {
                let mut buf = vec![0u8; ds.size() as usize];
                ds.read_at(0, &mut buf).unwrap();
                buf
            };
            let objects = entries[0].data.as_ref().unwrap();
            assert!(objects.supports_siblings());
            assert_eq!(
                read(
                    objects
                        .open_relative("MAPPING2.MAP")
                        .expect("MAPPING2 beside OBJECTS")
                ),
                b"map two"
            );
            assert_eq!(
                read(objects.open_relative("mapping1.map").unwrap()),
                b"map one"
            );
            assert_eq!(
                read(objects.open_relative("MAPPING3.MAP").unwrap()),
                b"map three"
            );
            assert_eq!(read(objects.open_relative("INDEX.BTR").unwrap()), b"index");
            assert!(objects.open_relative("unrelated.log").is_none());
            assert_eq!(read(objects.clone()), b"objects");
            // Outside a wbem/repository directory nothing is grouped.
            assert!(entries[7]
                .data
                .as_ref()
                .unwrap()
                .open_relative("MAPPING1.MAP")
                .is_none());
        }

        #[test]
        fn a_deleted_mapping_file_is_not_attached_to_objects_data() {
            let repo = "/Windows/System32/wbem/Repository";
            let mut entries = vec![
                entry(&format!("{repo}/OBJECTS.DATA"), b"objects", json!({})),
                entry(&format!("{repo}/MAPPING1.MAP"), b"live", json!({})),
                entry(
                    &format!("{repo}/MAPPING2.MAP"),
                    b"stale",
                    json!({ "deleted": true }),
                ),
                // A name present twice in one directory is not chosen between.
                entry(&format!("{repo}/MAPPING3.MAP"), b"first", json!({})),
                entry(&format!("{repo}/mapping3.map"), b"second", json!({})),
            ];
            attach_sibling_bundles(&mut entries);
            let objects = entries[0].data.as_ref().unwrap();
            assert!(objects.open_relative("MAPPING1.MAP").is_some());
            assert!(
                objects.open_relative("MAPPING2.MAP").is_none(),
                "a deleted mapping file is stale bytes and is not attached"
            );
            assert!(objects.open_relative("MAPPING3.MAP").is_none());
            // Withheld, not absent: the reader must be able to tell the two apart.
            assert!(
                objects.relative_withheld("MAPPING3.MAP"),
                "a name present twice is withheld, and the bundle says so"
            );
            assert!(!objects.relative_withheld("MAPPING2.MAP"));
            assert!(!objects.relative_withheld("INDEX.BTR"));
        }

        #[test]
        fn a_repository_whose_only_neighbour_is_duplicated_still_says_it_was_withheld() {
            let repo = "/Windows/System32/wbem/Repository";
            let mut entries = vec![
                entry(&format!("{repo}/OBJECTS.DATA"), b"objects", json!({})),
                entry(&format!("{repo}/MAPPING1.MAP"), b"first", json!({})),
                entry(&format!("{repo}/Mapping1.map"), b"second", json!({})),
            ];
            attach_sibling_bundles(&mut entries);
            let objects = entries[0].data.as_ref().unwrap();
            assert!(objects.open_relative("MAPPING1.MAP").is_none());
            assert!(objects.relative_withheld("mapping1.map"));
            // Nothing was attached, so whether the source can look is still its
            // inner source's answer: the withheld name does not change it.
            assert!(!objects.supports_siblings());
        }

        #[test]
        fn the_xp_fs_repository_directory_is_grouped_too() {
            let repo = "/WINDOWS/system32/wbem/Repository/FS";
            let mut entries = vec![
                entry(&format!("{repo}/OBJECTS.DATA"), b"objects", json!({})),
                entry(&format!("{repo}/MAPPING.VER"), b"ver", json!({})),
                entry(&format!("{repo}/MAPPING1.MAP"), b"one", json!({})),
                entry(&format!("{repo}/MAPPING2.MAP"), b"two", json!({})),
            ];
            attach_sibling_bundles(&mut entries);
            let objects = entries[0].data.as_ref().unwrap();
            let read = |ds: Arc<dyn DataSource>| {
                let mut buf = vec![0u8; ds.size() as usize];
                ds.read_at(0, &mut buf).unwrap();
                buf
            };
            assert_eq!(read(objects.open_relative("MAPPING.VER").unwrap()), b"ver");
            assert_eq!(read(objects.open_relative("MAPPING2.MAP").unwrap()), b"two");
        }

        /// "Could not look" and "looked, not there" (HUNT-101): a bundle that
        /// carries something was built from the listing, so it can answer the
        /// second; an empty bundle over a source that cannot look cannot.
        #[test]
        fn a_bundle_can_look_only_when_something_was_bundled() {
            let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"x".to_vec()));
            assert!(!SiblingBundleSource::new(inner.clone(), HashMap::new()).supports_siblings());
            let mut sibs = HashMap::new();
            sibs.insert("-wal".to_string(), inner.clone());
            assert!(SiblingBundleSource::new(inner, sibs).supports_siblings());
        }

        #[test]
        fn deleted_sidecars_are_not_attached() {
            // A `-wal` recovered from reallocated clusters is stale bytes, and a
            // mismatched WAL can make SQLite reject the database outright.
            let mut entries = vec![
                entry("/data/app.db", b"SQLite", json!({})),
                entry("/data/app.db-wal", b"stale", json!({ "deleted": true })),
            ];
            attach_sibling_bundles(&mut entries);
            assert!(entries[0]
                .data
                .as_ref()
                .unwrap()
                .open_sibling("-wal")
                .is_none());
        }

        #[test]
        fn suffix_case_and_directories_are_handled() {
            // `.log1` on disk must still answer the canonical `.LOG1` lookup,
            // and a directory is never treated as a sidecar.
            let mut entries = vec![
                entry("/config/SAM", b"regf", json!({})),
                entry("/config/SAM.log1", b"lower", json!({})),
                entry("/config/SAM.LOG2", b"", json!({ "is_directory": true })),
            ];
            attach_sibling_bundles(&mut entries);
            assert_eq!(
                sibling_bytes(&entries[0], ".LOG1").as_deref(),
                Some(&b"lower"[..])
            );
            assert!(entries[0]
                .data
                .as_ref()
                .unwrap()
                .open_sibling(".LOG2")
                .is_none());
        }
    }

    #[test]
    fn delegates_open_sibling_to_inner_when_not_attached() {
        // Inner is itself a bundle carrying ".LOG2"; the outer bundle carries
        // ".LOG1". A lookup the outer bundle doesn't hold must reach the inner.
        let hive: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 4]));
        let log2: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"two".to_vec()));
        let mut inner_sibs = HashMap::new();
        inner_sibs.insert(".LOG2".to_string(), log2);
        let inner: Arc<dyn DataSource> = Arc::new(SiblingBundleSource::new(hive, inner_sibs));

        let log1: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"one".to_vec()));
        let mut outer_sibs = HashMap::new();
        outer_sibs.insert(".LOG1".to_string(), log1);
        let outer = SiblingBundleSource::new(inner, outer_sibs);

        assert!(outer.open_sibling(".LOG1").is_some());
        assert!(outer.open_sibling(".LOG2").is_some());
        assert!(outer.open_sibling(".LOG").is_none());
    }

    /// A file-backed source opens a neighbour by path relative to its own
    /// directory — the shard folder beside an iOS backup's `Manifest.db`
    /// (HUNT-109) — and refuses a path that climbs, is absolute, or names a
    /// directory.
    /// HUNT-114. A deferred source holds no file descriptor until its first
    /// read, so a directory walk can make tens of thousands of them without
    /// running the process out of descriptors. Observed on Linux by counting
    /// this process's open fds before and after making many deferred sources.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_deferred_source_holds_no_descriptor_until_the_first_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"hello").unwrap();

        let fd_count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let before = fd_count();

        // A thousand deferred sources over the same file: sized now, unopened.
        let sources: Vec<FileDataSource> = (0..1000)
            .map(|_| FileDataSource::deferred(path.clone()).unwrap())
            .collect();
        assert!(
            fd_count() <= before + 4,
            "1000 deferred sources must not each hold a descriptor (before {before}, now {})",
            fd_count()
        );
        assert_eq!(sources[0].size(), 5, "sized without opening");

        // Reading opens the file; the bytes are correct.
        let mut buf = [0u8; 5];
        assert_eq!(sources[500].read_at(0, &mut buf).unwrap(), 5);
        assert_eq!(&buf, b"hello");

        // A deferred source over a directory is refused, since it is not a file.
        assert!(FileDataSource::deferred(dir.path().to_path_buf()).is_err());
    }

    #[test]
    fn file_source_opens_a_neighbour_by_relative_path_but_not_a_climbing_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("backup/3d")).unwrap();
        std::fs::write(dir.path().join("backup/Manifest.db"), b"manifest").unwrap();
        std::fs::write(dir.path().join("backup/3d/3d0d7e5f"), b"sms database").unwrap();
        std::fs::write(dir.path().join("secret.txt"), b"above").unwrap();

        let manifest = FileDataSource::new(dir.path().join("backup/Manifest.db")).unwrap();
        assert!(manifest.supports_siblings());
        let blob = manifest
            .open_relative("3d/3d0d7e5f")
            .expect("the blob beside it");
        let mut buf = vec![0u8; blob.size() as usize];
        blob.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, b"sms database");

        assert!(manifest.open_relative("3d/absent").is_none());
        assert!(
            manifest.open_relative("3d").is_none(),
            "a directory is not a file"
        );
        assert!(manifest.open_relative("../secret.txt").is_none());
        assert!(manifest.open_relative("").is_none());
        assert!(manifest
            .open_relative(&dir.path().join("secret.txt").to_string_lossy())
            .is_none());

        // The bundle wrapper a filesystem walker puts around a file delegates.
        let bundled = SiblingBundleSource::new(Arc::new(manifest), HashMap::new());
        assert!(bundled.open_relative("3d/3d0d7e5f").is_some());
    }

    #[test]
    fn relative_path_is_plain_rejects_every_way_of_climbing() {
        assert!(relative_path_is_plain("3d/3d0d7e5f"));
        assert!(relative_path_is_plain("Manifest.db"));
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "./a",
            "a//b",
            "a\\b",
            "a/",
        ] {
            assert!(!relative_path_is_plain(bad), "{bad:?} must be refused");
        }
    }
}

#[cfg(test)]
mod physical_map_tests {
    use super::*;

    fn dev(size: u64) -> Arc<dyn DataSource> {
        // Stand-in device image with no real file backing.
        Arc::new(DeviceImageSource::new(Arc::new(ByteSliceDataSource::new(
            vec![0u8; size as usize],
        ))))
    }

    /// A window over a device image projects to a single shifted exact extent.
    #[test]
    fn window_projects_to_shifted_offset() {
        let w = WindowSource::new(dev(10_000), 1_000, 500);
        let map = w.physical_map(0, 500);
        assert_eq!(map.precision, ExtentPrecision::Exact);
        assert_eq!(map.extents, vec![PhysicalExtent::device(1_000, 500)]);
    }

    /// A fragmented run list projects a single contiguous logical range to
    /// multiple device extents (one per fragment), through a partition window.
    #[test]
    fn fragmented_runlist_yields_multiple_device_extents() {
        // Device -> partition window at 2048 -> file with two fragments.
        let partition = Arc::new(WindowSource::new(dev(1_000_000), 2_048, 900_000));
        // Runs are relative to the partition window.
        let runs = vec![(Some(100), 400), (Some(10_000), 600)];
        let file = RunListDataSource::from_allocation(partition, runs);
        let map = file.physical_map(0, 1_000).coalesce();
        assert_eq!(map.precision, ExtentPrecision::Exact);
        // Each run + the partition base 2048.
        assert_eq!(
            map.extents,
            vec![
                PhysicalExtent::device(2_148, 400),
                PhysicalExtent::device(12_048, 600),
            ]
        );
        assert_eq!(map.located_len(), 1_000);
    }

    /// Sparse runs report a hole (no device offset) but stay Exact (it is exact
    /// knowledge that no bytes back the region).
    #[test]
    fn sparse_run_reports_hole() {
        let dev = dev(100_000);
        let runs = vec![(Some(500), 200), (None, 300), (Some(4_000), 100)];
        let file = RunListDataSource::from_allocation(dev, runs);
        let map = file.physical_map(0, 600);
        assert_eq!(map.precision, ExtentPrecision::Exact);
        assert_eq!(map.extents.len(), 3);
        assert_eq!(map.extents[1].device_offset, None);
        assert_eq!(map.extents[1].length, 300);
        assert_eq!(map.located_len(), 300);
    }

    /// The nested case: a file inside a filesystem inside a fragmented `.dd`
    /// image that is itself fragmented in the outer filesystem. A contiguous
    /// inner range must split across the outer `.dd` fragments.
    #[test]
    fn nested_image_fragments_through_outer_container() {
        // Outer device.
        let outer_dev = dev(10_000_000);
        // The inner `.dd` is a file in the outer fs, fragmented into two pieces
        // at outer-device offsets 1_000_000 (len 1000) and 5_000_000 (len 1000).
        let dd_file = Arc::new(RunListDataSource::from_allocation(
            outer_dev,
            vec![(Some(1_000_000), 1_000), (Some(5_000_000), 1_000)],
        ));
        // A filesystem window inside the `.dd` starting at inner offset 0.
        let inner_fs = Arc::new(WindowSource::new(dd_file, 0, 2_000));
        // An inner file occupying a single contiguous run [800, 400) that
        // straddles the `.dd`'s fragment boundary at inner offset 1000.
        let inner_file = RunListDataSource::from_allocation(inner_fs, vec![(Some(800), 400)]);
        let map = inner_file.physical_map(0, 400).coalesce();
        assert_eq!(map.precision, ExtentPrecision::Exact);
        // 800..1000 -> outer 1_000_800..1_001_000 (200 bytes),
        // 1000..1200 -> outer 5_000_000..5_000_200 (200 bytes).
        assert_eq!(
            map.extents,
            vec![
                PhysicalExtent::device(1_000_800, 200),
                PhysicalExtent::device(5_000_000, 200),
            ]
        );
    }

    /// In-memory content (resident data, decompressed files, ZIP entries) has no
    /// device backing: the default projection is opaque/Synthetic.
    #[test]
    fn byte_slice_is_synthetic() {
        let bs = ByteSliceDataSource::new(vec![1, 2, 3, 4]);
        let map = bs.physical_map(0, 4);
        assert_eq!(map.precision, ExtentPrecision::Synthetic);
        assert_eq!(map.extents, vec![PhysicalExtent::hole(4)]);
    }

    /// Worst-case precision propagates: a run list over synthetic inner content
    /// degrades to Synthetic even though the run offsets are known.
    #[test]
    fn precision_degrades_to_worst_across_chain() {
        let synthetic_inner = Arc::new(ByteSliceDataSource::new(vec![0u8; 1_000]));
        let file = RunListDataSource::from_allocation(synthetic_inner, vec![(Some(0), 500)]);
        let map = file.physical_map(0, 500);
        assert_eq!(map.precision, ExtentPrecision::Synthetic);
    }

    /// BUG-093: a run list whose lengths overflow u64 must saturate the total,
    /// not wrap to a tiny size (which would mis-map reads onto wrong bytes).
    #[test]
    fn run_list_total_size_saturates_on_overflow() {
        let inner = Arc::new(ByteSliceDataSource::new(vec![0u8; 16]));
        let file =
            RunListDataSource::from_allocation(inner, vec![(Some(0), u64::MAX), (Some(0), 100)]);
        assert_eq!(file.size(), u64::MAX, "sum must saturate, not wrap small");
    }

    /// BUG-128: byte_runs_to_metadata must not coalesce two runs when the first
    /// run's end offset would wrap u64 into the second's start.
    #[test]
    fn byte_runs_metadata_does_not_coalesce_on_wrap() {
        // last_off + last_len wraps to 0; the next run starts at 0. A wrapping
        // "contiguity" test would merge them -- it must not.
        let runs = [(Some(u64::MAX), 1u64), (Some(0), 8u64)];
        let (value, _complete) = byte_runs_to_metadata(&runs);
        let arr = value.as_array().unwrap();
        assert_eq!(
            arr.len(),
            2,
            "wrapping runs must stay separate, not coalesce"
        );
    }

    /// B3-008: `PhysicalMap::coalesce` must not treat a wrapping end offset as
    /// adjacency. The examiner learns where a file's bytes physically live; a
    /// wrapped `device_offset + length` would merge two unrelated regions and
    /// report bytes as coming from an offset they were never read from.
    #[test]
    fn physical_map_does_not_coalesce_on_wrapping_offset() {
        let map = PhysicalMap::on_device(
            vec![
                PhysicalExtent::device(u64::MAX, 1),
                PhysicalExtent::device(0, 8),
            ],
            ExtentPrecision::Exact,
        )
        .coalesce();
        assert_eq!(
            map.extents.len(),
            2,
            "extents whose adjacency only holds under wrapping must stay separate"
        );
    }

    /// B3-008: merging two contiguous extents whose combined length overflows
    /// u64 must keep them separate. A wrapped merge would shrink the map to a
    /// few bytes, so a download or hash would silently stop at the wrong place.
    #[test]
    fn physical_map_does_not_merge_when_length_overflows() {
        let map = PhysicalMap::on_device(
            vec![
                PhysicalExtent::device(0, u64::MAX),
                PhysicalExtent::device(u64::MAX, 4),
            ],
            ExtentPrecision::Exact,
        )
        .coalesce();
        assert_eq!(map.extents.len(), 2, "an overflowing merge must not wrap");
        assert_eq!(map.extents[0].length, u64::MAX);
        assert_eq!(map.extents[1].length, 4);
    }

    /// B3-008: extent totals saturate. Reporting a 3-byte total for a map that
    /// covers more than u64::MAX bytes would understate the evidence.
    #[test]
    fn physical_map_totals_saturate_on_overflow() {
        let map = PhysicalMap::on_device(
            vec![
                PhysicalExtent::device(0, u64::MAX),
                PhysicalExtent::device(4096, 4),
                PhysicalExtent::hole(u64::MAX),
            ],
            ExtentPrecision::Exact,
        );
        assert_eq!(map.total_len(), u64::MAX);
        assert_eq!(map.located_len(), u64::MAX);
    }

    /// A source whose size does not fit in `i64`.
    #[derive(Debug)]
    struct HugeSource;

    impl DataSource for HugeSource {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn size(&self) -> u64 {
            u64::MAX
        }
    }

    /// B3-008 family: `SourceCursor::seek` must address the whole `u64` range.
    ///
    /// What an examiner learns: a parser can reach the tail of a very large
    /// source. The wrong answer this guards against is an `InvalidInput`
    /// "negative position" on a perfectly ordinary end-relative seek — the old
    /// `size as i64` reinterpreted every offset above `i64::MAX` as negative,
    /// so the parser would report the evidence unreadable rather than read it.
    #[test]
    fn source_cursor_seek_addresses_offsets_above_i64_max() {
        let mut cursor = SourceCursor::new(Arc::new(HugeSource) as Arc<dyn DataSource>);
        assert_eq!(cursor.seek(SeekFrom::End(0)).unwrap(), u64::MAX);
        assert_eq!(cursor.seek(SeekFrom::Start(u64::MAX)).unwrap(), u64::MAX);
        assert_eq!(cursor.seek(SeekFrom::Current(-1)).unwrap(), u64::MAX - 1);
        // Still fails closed on a genuinely impossible target.
        assert!(cursor.seek(SeekFrom::End(1)).is_err());
        assert!(cursor.seek(SeekFrom::Start(0)).is_ok());
        assert!(cursor.seek(SeekFrom::Current(-1)).is_err());
    }
}

#[cfg(test)]
mod logical_size_tests {
    /// **A poisoned cache must not deny an examiner the evidence.**
    ///
    /// `Mutex::lock` returns `Err` for every caller once any thread has
    /// panicked while holding the guard — not once, but forever. Unwrapping
    /// turned a single request-level panic into a permanent failure of every
    /// cached read in the process: the tool simply stopped returning evidence
    /// until it was restarted, with no message saying why.
    ///
    /// Recovering the guard is safe because a cache holds *derived* data. The
    /// worst case is a stale entry; the worst case of refusing is unreachable
    /// evidence.
    #[test]
    fn a_poisoned_cache_lock_still_serves_reads() {
        let inner: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new((0..=255u8).collect()));
        let cached = Arc::new(CachingDataSource::new(Arc::clone(&inner), 16, 256));

        // Warm it, so the cache is genuinely in use.
        let mut buf = [0u8; 8];
        assert_eq!(cached.read_at(0, &mut buf).expect("first read"), 8);

        // Poison the lock exactly as a panicking request would.
        let poisoner = Arc::clone(&cached);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.cache.lock().expect("not yet poisoned");
            panic!("a request panicked while holding the cache lock");
        })
        .join();

        let mut after = [0u8; 8];
        let read = cached
            .read_at(0, &mut after)
            .expect("a poisoned cache must not make the evidence unreadable");
        assert_eq!(read, 8);
        assert_eq!(after, buf, "and it must still return the right bytes");

        // A cold chunk too, so the put-path is exercised under poisoning as
        // well as the get-path.
        let mut cold = [0u8; 8];
        assert_eq!(cached.read_at(200, &mut cold).expect("cold read"), 8);
        assert_eq!(cold[0], 200);
    }

    use super::*;

    /// Bytes 0..64, so a wrong offset or length is visible in the value read.
    fn ramp() -> Arc<dyn DataSource> {
        Arc::new(ByteSliceDataSource::new((0u8..64).collect::<Vec<u8>>()))
    }

    /// A run list allocates whole clusters; a file ends partway through the
    /// last one. The bytes after that end belong to whatever occupied the
    /// cluster before, and serving them as this file's content puts a stranger's
    /// data into its hex view, download, export and hash (B2-064).
    #[test]
    fn trailing_cluster_slack_is_not_served_as_file_content() {
        // Two 16-byte "clusters" allocated; the file is 20 bytes.
        let runs = vec![(Some(0u64), 16u64), (Some(16u64), 16u64)];
        let file = RunListDataSource::with_logical_size(ramp(), runs.clone(), 20);

        assert_eq!(file.size(), 20, "the file is its logical length, not 32");

        let mut buf = vec![0u8; 32];
        let read = file.read_at(0, &mut buf).expect("readable");
        assert_eq!(read, 20, "a read past the logical end stops at it");
        assert_eq!(&buf[..20], &(0u8..20).collect::<Vec<u8>>()[..]);

        // The same runs, taken as an allocation, still serve all 32 — that is
        // the correct answer to a different question, and the two constructors
        // exist so a caller has to say which it is asking.
        let allocation = RunListDataSource::from_allocation(ramp(), runs);
        assert_eq!(allocation.size(), 32);
    }

    /// The other direction, which the resolver already handled and which the
    /// constructor must not lose: a file longer than its runs has a trailing
    /// unallocated hole, and reads to its full length as zeros rather than
    /// stopping early (BUG-154).
    #[test]
    fn a_file_longer_than_its_runs_reads_to_its_full_length() {
        let file = RunListDataSource::with_logical_size(ramp(), vec![(Some(0u64), 8u64)], 12);

        assert_eq!(file.size(), 12);
        let mut buf = vec![0u8; 12];
        assert_eq!(file.read_at(0, &mut buf).expect("readable"), 12);
        assert_eq!(&buf[..8], &(0u8..8).collect::<Vec<u8>>()[..]);
        assert_eq!(&buf[8..], &[0, 0, 0, 0], "the hole reads as zeros");
    }

    /// A run cut to nothing is dropped rather than kept at zero length, so the
    /// cumulative table stays strictly increasing and the binary search in
    /// `find_run` cannot land on a run it can read no bytes from.
    #[test]
    fn a_run_trimmed_to_nothing_is_dropped_rather_than_kept_empty() {
        let runs = vec![(Some(0u64), 8u64), (Some(8u64), 8u64), (Some(16u64), 8u64)];
        let fitted = fit_runs_to_logical(runs, 8);
        assert_eq!(fitted, vec![(Some(0u64), 8u64)]);
        assert!(
            fitted.iter().all(|(_, len)| *len > 0),
            "no zero-length run survives"
        );
    }

    /// Exact fit is the common case and must not disturb the run list.
    #[test]
    fn runs_that_already_match_are_returned_unchanged() {
        let runs = vec![(Some(0u64), 8u64), (Some(32u64), 4u64)];
        assert_eq!(fit_runs_to_logical(runs.clone(), 12), runs);
    }

    /// A corrupt run list whose lengths sum past u64::MAX must not fold to a
    /// small total and turn the fit into a multi-exabyte sparse pad, which
    /// would fabricate zero bytes into every read of the file (BUG-093).
    #[test]
    fn a_run_list_summing_past_u64_max_does_not_become_a_sparse_pad() {
        let runs = vec![(Some(0u64), u64::MAX), (Some(0u64), 100u64)];
        let fitted = fit_runs_to_logical(runs, 64);
        let total: u64 = fitted.iter().map(|(_, len)| *len).sum();
        assert_eq!(total, 64, "trimmed to the logical size, not padded past it");
        assert!(fitted.iter().all(|(start, _)| start.is_some()));
    }
}

/// `open_from_ancestor`: the bounded climb a unified log uses to reach its
/// tree (ROADMAP §1.6).
#[cfg(test)]
mod ancestor_tests {
    use super::*;

    fn read_all(s: Arc<dyn DataSource>) -> Vec<u8> {
        let mut buf = vec![0u8; s.size() as usize];
        let n = s.read_at(0, &mut buf).unwrap();
        buf.truncate(n);
        buf
    }

    #[test]
    fn a_file_reaches_a_neighbour_one_and_two_directories_up() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("db/diagnostics/Persist")).unwrap();
        std::fs::create_dir_all(root.join("db/diagnostics/timesync")).unwrap();
        std::fs::create_dir_all(root.join("db/uuidtext/AB")).unwrap();
        std::fs::write(root.join("db/diagnostics/Persist/1.tracev3"), b"log").unwrap();
        std::fs::write(root.join("db/diagnostics/timesync/2.timesync"), b"ts").unwrap();
        std::fs::write(root.join("db/uuidtext/AB/CD"), b"strings").unwrap();
        let log = FileDataSource::new(root.join("db/diagnostics/Persist/1.tracev3")).unwrap();
        assert!(log.supports_ancestors());
        assert_eq!(
            read_all(log.open_from_ancestor(1, "timesync/2.timesync").unwrap()),
            b"ts"
        );
        assert_eq!(
            read_all(log.open_from_ancestor(2, "uuidtext/AB/CD").unwrap()),
            b"strings"
        );
        assert!(log.open_from_ancestor(1, "uuidtext/AB/CD").is_none());
    }

    #[test]
    fn a_file_lists_a_directory_under_an_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("arch/Persist")).unwrap();
        std::fs::create_dir_all(root.join("arch/timesync/sub")).unwrap();
        std::fs::write(root.join("arch/Persist/1.tracev3"), b"log").unwrap();
        std::fs::write(root.join("arch/timesync/00000000000001f4.timesync"), b"b").unwrap();
        std::fs::write(root.join("arch/timesync/0000000000000040.timesync"), b"a").unwrap();
        let log = FileDataSource::new(root.join("arch/Persist/1.tracev3")).unwrap();
        // Sorted, and the sub-directory is not a file.
        assert_eq!(
            log.list_from_ancestor(1, "timesync"),
            Some(vec![
                "0000000000000040.timesync".to_string(),
                "00000000000001f4.timesync".to_string()
            ])
        );
        assert_eq!(
            log.list_from_ancestor(0, ""),
            Some(vec!["1.tracev3".to_string()])
        );
        assert_eq!(log.list_from_ancestor(1, "absent"), None);
        assert_eq!(log.list_from_ancestor(1, "../arch"), None);
        assert_eq!(log.list_from_ancestor(4, "timesync"), None);
        // Wrappers pass the listing through; bytes cannot list.
        let cached = CachingDataSource::new(Arc::new(log), 4096, 1 << 20);
        assert_eq!(
            cached.list_from_ancestor(1, "timesync").map(|v| v.len()),
            Some(2)
        );
        assert_eq!(
            ByteSliceDataSource::new(vec![0; 4]).list_from_ancestor(0, ""),
            None
        );
    }

    #[test]
    fn the_climb_is_bounded_and_the_path_must_be_plain() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("a/b/c/d/e");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(dir.path().join("a/top"), b"x").unwrap();
        std::fs::write(deep.join("f"), b"y").unwrap();
        let f = FileDataSource::new(deep.join("f")).unwrap();
        // `a/` is four levels above `e/`: past the bound, refused.
        assert!(f.open_from_ancestor(4, "top").is_none());
        assert!(f.open_from_ancestor(3, "../top").is_none());
        assert!(f.open_from_ancestor(3, "/etc/passwd").is_none());
        assert!(f.open_from_ancestor(0, "f").is_some());
    }

    #[test]
    fn wrappers_pass_the_climb_through_and_bytes_cannot_climb() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("x/y")).unwrap();
        std::fs::write(dir.path().join("x/n"), b"n").unwrap();
        std::fs::write(dir.path().join("x/y/f"), b"f").unwrap();
        let inner: Arc<dyn DataSource> =
            Arc::new(FileDataSource::new(dir.path().join("x/y/f")).unwrap());
        let cached = CachingDataSource::new(inner.clone(), 4096, 4);
        assert!(cached.supports_ancestors());
        assert!(cached.open_from_ancestor(1, "n").is_some());
        let buffered = BufferedDataSource::new(inner.clone(), 4096);
        assert!(buffered.open_from_ancestor(1, "n").is_some());
        let bundle = SiblingBundleSource::new(inner, Default::default());
        assert!(bundle.open_from_ancestor(1, "n").is_some());
        let bytes = ByteSliceDataSource::new(b"z".to_vec());
        assert!(!bytes.supports_ancestors());
        assert!(bytes.open_from_ancestor(1, "n").is_none());
    }

    #[test]
    fn an_entry_names_ancestor_prefix_stays_inside_the_name() {
        assert_eq!(
            ancestor_prefix("a.logarchive/Persist/1.tracev3", 1).as_deref(),
            Some("a.logarchive/")
        );
        assert_eq!(
            ancestor_prefix("a.logarchive/Persist/1.tracev3", 2).as_deref(),
            Some("")
        );
        assert_eq!(ancestor_prefix("a.logarchive/Persist/1.tracev3", 3), None);
        assert_eq!(ancestor_prefix("x/1", 0).as_deref(), Some("x/"));
        assert_eq!(ancestor_prefix("a/b/c/d/e/f", 4), None);
    }
}

#[cfg(test)]
mod decrypted_range_tests {
    use super::*;

    #[test]
    fn a_decrypted_read_is_clamped_to_the_plaintext_and_fills_the_front_of_the_buffer() {
        let decrypt = |offset: u64, want: usize| -> Result<Vec<u8>, String> {
            Ok((0..want).map(|i| (offset as usize + i) as u8).collect())
        };
        let mut buf = [0u8; 8];
        // 10 bytes of plaintext; asking for 8 at offset 6 yields 4.
        assert_eq!(read_decrypted_range(10, 6, &mut buf, decrypt).unwrap(), 4);
        assert_eq!(&buf[..4], &[6, 7, 8, 9]);
        // At or past the end, or an empty buffer, reads nothing and never decrypts.
        let never = |_: u64, _: usize| -> Result<Vec<u8>, String> { panic!("must not decrypt") };
        assert_eq!(read_decrypted_range(10, 10, &mut buf, never).unwrap(), 0);
        assert_eq!(read_decrypted_range(10, 0, &mut [], never).unwrap(), 0);
    }

    #[test]
    fn a_decryption_failure_is_an_error_never_a_short_or_zero_read() {
        let mut buf = [0xAAu8; 4];
        let err = read_decrypted_range(100, 0, &mut buf, |_, _| -> Result<Vec<u8>, String> {
            Err("sector failed its integrity check".to_string())
        })
        .unwrap_err();
        assert!(err.to_string().contains("integrity"));
        assert_eq!(buf, [0xAA; 4], "the caller's buffer is untouched");
    }
}

#[cfg(test)]
mod unified_log_tree_tests {
    use super::*;
    use crate::artifact::{Artifact, ArtifactType};
    use serde_json::json;
    use uuid::Uuid;

    fn entry(path: &str, bytes: &[u8], extra: serde_json::Value) -> Artifact {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes.to_vec()));
        let mut md = json!({ "name": path.rsplit('/').next().unwrap(), "path": path });
        if let (Some(o), Some(e)) = (md.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                o.insert(k.clone(), v.clone());
            }
        }
        Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, Some(ds), md)
    }

    fn bytes(ds: Arc<dyn DataSource>) -> Vec<u8> {
        let mut buf = vec![0u8; ds.size() as usize];
        ds.read_at(0, &mut buf).unwrap();
        buf
    }

    /// A macOS log tree as a filesystem walk lists it.
    fn log_tree() -> Vec<Artifact> {
        vec![
            entry(
                "/var/db/diagnostics/Persist/0000000000000001.tracev3",
                b"persist-1",
                json!({}),
            ),
            entry(
                "/var/db/diagnostics/Persist/0000000000000002.tracev3",
                b"persist-2",
                json!({}),
            ),
            entry(
                "/var/db/diagnostics/Special/0000000000000003.tracev3",
                b"special",
                json!({}),
            ),
            entry(
                "/var/db/diagnostics/timesync/0000000000000001.timesync",
                b"ts-1",
                json!({}),
            ),
            entry(
                "/var/db/diagnostics/timesync/0000000000000009.timesync",
                b"ts-9",
                json!({}),
            ),
            entry("/var/db/uuidtext/AB/CDEF0123456789", b"uuidtext", json!({})),
            entry("/var/db/uuidtext/dsc/9999", b"dsc", json!({})),
            entry("/etc/hosts", b"127.0.0.1", json!({})),
        ]
    }

    #[test]
    fn a_wal_attaches_to_the_live_base_not_a_deleted_one_at_the_same_path() {
        for deleted_first in [true, false] {
            let stale = entry("/p/History", b"stale", json!({ "deleted": true }));
            let live = entry("/p/History", b"live", json!({}));
            let wal = entry("/p/History-wal", b"wal", json!({}));
            let mut entries = if deleted_first {
                vec![stale, live, wal]
            } else {
                vec![live, stale, wal]
            };
            attach_sibling_bundles(&mut entries);
            let (live_i, stale_i) = if deleted_first { (1, 0) } else { (0, 1) };
            let live_src = entries[live_i].data.clone().unwrap();
            assert!(live_src.supports_siblings(), "live base must get the WAL");
            assert!(live_src.open_sibling("-wal").is_some());
            assert!(!entries[stale_i].data.clone().unwrap().supports_siblings());
        }
    }

    #[test]
    fn a_tracev3_in_a_listing_reaches_its_uuidtext_and_timesync_neighbours() {
        let mut entries = log_tree();
        attach_sibling_bundles(&mut entries);
        let src = entries[0].data.clone().unwrap();
        assert!(src.supports_ancestors());
        // `/var/db/diagnostics/Persist/x.tracev3`: one up is `Persist`'s parent.
        assert_eq!(
            bytes(
                src.open_from_ancestor(1, "timesync/0000000000000009.timesync")
                    .unwrap()
            ),
            b"ts-9"
        );
        assert_eq!(
            bytes(
                src.open_from_ancestor(2, "uuidtext/AB/CDEF0123456789")
                    .unwrap()
            ),
            b"uuidtext"
        );
        assert_eq!(
            bytes(src.open_from_ancestor(2, "uuidtext/dsc/9999").unwrap()),
            b"dsc"
        );
        assert!(src.open_from_ancestor(2, "uuidtext/AB/not-there").is_none());
        // Still reads as the same file.
        assert_eq!(bytes(src.clone()), b"persist-1");
    }

    #[test]
    fn a_directory_is_listed_sorted_with_only_the_files_directly_in_it() {
        let mut entries = log_tree();
        attach_sibling_bundles(&mut entries);
        let src = entries[0].data.clone().unwrap();
        assert_eq!(
            src.list_from_ancestor(1, "timesync").unwrap(),
            vec!["0000000000000001.timesync", "0000000000000009.timesync"]
        );
        // Every `.tracev3` of the tree, found by listing its directories.
        assert_eq!(
            src.list_from_ancestor(0, "").unwrap(),
            vec!["0000000000000001.tracev3", "0000000000000002.tracev3"]
        );
        assert!(src.list_from_ancestor(1, "no-such-directory").is_none());
    }

    #[test]
    fn a_file_with_no_tracev3_beside_it_is_left_alone() {
        let mut entries = log_tree();
        attach_sibling_bundles(&mut entries);
        let hosts = entries[7].data.clone().unwrap();
        assert!(!hosts.supports_ancestors(), "only a tracev3 gets the tree");
    }

    #[test]
    fn a_listing_with_no_tracev3_is_not_indexed_at_all() {
        let mut entries = vec![
            entry("/var/db/uuidtext/AB/CDEF", b"uuidtext", json!({})),
            entry("/etc/hosts", b"h", json!({})),
        ];
        attach_sibling_bundles(&mut entries);
        assert!(!entries[0].data.clone().unwrap().supports_ancestors());
    }

    #[test]
    fn a_deleted_file_is_never_served_as_part_of_the_tree() {
        // Stale bytes from reallocated clusters would be decoded as a format
        // string table that was never this machine's.
        let mut entries = log_tree();
        entries.push(entry(
            "/var/db/uuidtext/AB/DELETED000",
            b"stale",
            json!({ "deleted": true }),
        ));
        attach_sibling_bundles(&mut entries);
        let src = entries[0].data.clone().unwrap();
        assert!(src
            .open_from_ancestor(2, "uuidtext/AB/DELETED000")
            .is_none());
    }

    #[test]
    fn the_climb_is_bounded_and_a_path_cannot_leave_the_tree() {
        let mut entries = log_tree();
        attach_sibling_bundles(&mut entries);
        let src = entries[0].data.clone().unwrap();
        assert!(src
            .open_from_ancestor(MAX_ANCESTOR_LEVELS + 1, "uuidtext/AB/CDEF0123456789")
            .is_none());
        assert!(
            src.open_from_ancestor(1, "../hosts").is_none(),
            "no `..` in a relative path"
        );
        assert!(
            src.open_from_ancestor(1, "/etc/hosts").is_none(),
            "no absolute path"
        );
    }

    #[test]
    fn a_case_insensitive_volume_still_finds_the_name_under_another_case() {
        let mut entries = vec![
            entry(
                "/var/db/diagnostics/Persist/0000000000000001.tracev3",
                b"p",
                json!({}),
            ),
            entry("/var/db/UUIDTEXT/ab/CDEF", b"uuidtext", json!({})),
        ];
        attach_sibling_bundles(&mut entries);
        let src = entries[0].data.clone().unwrap();
        assert_eq!(
            bytes(src.open_from_ancestor(2, "uuidtext/AB/CDEF").unwrap()),
            b"uuidtext"
        );
    }
}
