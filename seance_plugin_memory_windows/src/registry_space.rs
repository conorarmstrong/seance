//! [`HiveSpace`]: the hive's own address space, where an address is a **cell
//! index** and the bytes behind it are scattered across paged pool.
//!
//! # Why a registry hive in memory is not a registry hive on disk
//!
//! On disk a hive is one file: a base block, then bins, then cells, and a cell
//! index is simply a file offset (less the 4 KiB base block). In memory the
//! kernel loads each bin wherever it likes, and the file offsets stop meaning
//! anything. What restores the meaning is the hive's storage map, and every
//! read of an in-memory hive goes through it:
//!
//! ```text
//! cell index  ->  _HHIVE.Storage[bit 31]        the two stores
//!                   .Map                        _HMAP_DIRECTORY*
//!                   .Directory[bits 30..21]     _HMAP_TABLE*
//!                   .Table[bits 20..12]         _HMAP_ENTRY
//!                   + bits 11..0                offset inside the 4 KiB page
//! ```
//!
//! Three things about that walk decide whether the answer is evidence:
//!
//! **Bit 31 selects the store, and the two stores are different registries.**
//! Stable cells came from the hive file; *volatile* cells exist only in RAM and
//! have no on-disk counterpart at all — they are precisely the registry
//! evidence a disk image cannot show. Reading a volatile index out of the
//! stable map does not fail, it returns a different key, and it parses.
//!
//! **The map is per-hive.** Two hives' cell index `0x20` are two unrelated
//! keys. A [`HiveSpace`] is therefore bound to one `_CMHIVE` and never shared.
//!
//! **A bin that is paged out is not an empty bin.** Upstream pads unreadable
//! registry reads with NUL bytes; here an unmapped page is a
//! [`seance_memory::layer::MemoryHole`] that reaches the caller, because "this
//! value was empty" and "we never had this value" are opposite findings.
//!
//! # Windows 10 17063 and later
//!
//! From that build the kernel maps most hives through the *Registry* process
//! rather than into paged pool, so the `_HMAP_ENTRY` block addresses are only
//! resolvable in that process's address space. The `_CMHIVE` and the storage
//! map itself still live in kernel space.
//!
//! [`locate_bin_space`] decides which space this image keeps its bins in and
//! opens it, and [`HiveSpace::open_for_image`] is what every production path
//! uses. [`HiveSpace::open`] reads the bins from kernel space unconditionally,
//! which is correct up to Windows 10 1703 and, on later builds, yields honest
//! holes rather than wrong bytes — but holes an examiner cannot tell from
//! unacquired pages, which is why [`HiveSpace::bin_source`] travels with the
//! hive and says which of the two happened.

use std::sync::Arc;

use seance_core::io::read_exact_or_fail;
use seance_memory::binding::first_declared_member;
use seance_memory::layer::{LayerError, MappedRange, MemoryHole, MemoryLayer};
use seance_memory::meta::LayerMeta;
use seance_memory::object::{IntValue, Obj, ObjError, StructReader};
use seance_memory::translate::TableCache;
use seance_symbols::{SymbolError, SymbolTable, TypeId, TypeKind};

use crate::profile::{Evidence, Found, WindowsProfile};
use crate::registry::error::RegistryError;

/// `_HHIVE.Signature` of a live hive: `0xBEE0BEE0`.
///
/// The one fact that separates a `_CMHIVE` from any other pool allocation of a
/// similar size. A structure without it is refused rather than parsed, because
/// a wrong answer here is a whole key tree attributed to a hive that never
/// existed.
pub const HIVE_SIGNATURE: u64 = 0xBEE0_BEE0;

/// `_HBASE_BLOCK.Signature` of a hive base block: `"regf"` little-endian.
pub const HBASE_SIGNATURE: u64 = 0x6667_6572;

/// Bit 31 of a cell index: set for the volatile store, clear for the stable one.
pub const STORE_BIT: u32 = 0x8000_0000;

/// The cell index that means "no cell", written in the format as `-1`.
pub const HCELL_NIL: u32 = 0xFFFF_FFFF;

/// Size of the allocation header in front of every registry cell, in bytes.
///
/// This is a **hive file format** constant, not a kernel structure offset: every
/// cell begins with a signed 32-bit allocation size, and the cell's contents
/// start immediately after it. It has been four bytes in every version of the
/// format since Windows NT 3.1, on 32-bit and 64-bit alike, because the format
/// is the same file either way.
///
/// It is nonetheless cross-checked against the symbol table whenever the table
/// happens to describe `_HCELL` — see [`cell_header_len`] — so a build that
/// disagreed would be refused rather than silently read four bytes early.
pub const CELL_HEADER_LEN: u64 = 4;

/// Page granularity of the storage map. Each `_HMAP_ENTRY` covers one page.
pub const HIVE_PAGE_SIZE: u64 = 0x1000;

/// Cell index bit positions, from `_HHIVE`'s two-level map.
const DIRECTORY_SHIFT: u32 = 21;
const DIRECTORY_MASK: u32 = 0x3FF;
const TABLE_SHIFT: u32 = 12;
const TABLE_MASK: u32 = 0x1FF;
const PAGE_MASK: u32 = 0xFFF;

/// The root cell index of a hive whose base block could not be read.
///
/// `0x20` is where the format puts the root key: the first bin starts at hive
/// offset 0 and its 32-byte header is followed immediately by the root cell.
/// It is used **only** as a probe — a candidate to test — and never as an
/// answer on its own. See [`HiveSpace::root_cell`].
pub const PROBE_ROOT_CELL: u32 = 0x20;

/// Ceiling on a single read out of a hive, in bytes.
///
/// Registry values are attacker-controlled and `_CM_KEY_VALUE.DataLength` is a
/// 31-bit number, so a corrupt one would otherwise ask for two gigabytes.
/// Sixteen mebibytes is far above any real registry value and far below a
/// denial of service.
pub const MAX_CELL_READ: u64 = 16 << 20;

/// Which of a hive's two stores a cell index selects.
///
/// The distinction is forensic, not structural. A *volatile* key exists only
/// while the machine is running: it is in the memory image and it is in no disk
/// image anywhere, which is exactly why an examiner cares that it is labelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Store {
    /// Backed by the hive file. Survives a reboot.
    Stable,
    /// Created at boot and never written to disk. Lost at power-off, and
    /// recoverable only from memory.
    Volatile,
}

impl Store {
    /// Stable identifier for artifact metadata and report columns.
    pub fn as_str(self) -> &'static str {
        match self {
            Store::Stable => "stable",
            Store::Volatile => "volatile",
        }
    }

    /// Index of this store in `_HHIVE.Storage`.
    pub fn slot(self) -> u64 {
        match self {
            Store::Stable => 0,
            Store::Volatile => 1,
        }
    }
}

/// An address in a hive's own address space.
///
/// Deliberately a type rather than a bare `u32`: the store bit means that
/// ordinary arithmetic on a cell index is wrong. Adding four to `0x7FFFFFFC`
/// produces `0x80000000`, which is not "four bytes further on", it is the first
/// byte of the *other store*, and every key read through it would come from the
/// wrong half of the hive while parsing perfectly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CellIndex(u32);

impl CellIndex {
    /// A cell index exactly as it was read out of the image.
    pub fn new(raw: u32) -> Self {
        CellIndex(raw)
    }

    /// The index as stored, store bit included.
    pub fn raw(self) -> u32 {
        self.0
    }

    /// Which store this index addresses.
    pub fn store(self) -> Store {
        if self.0 & STORE_BIT != 0 {
            Store::Volatile
        } else {
            Store::Stable
        }
    }

    /// The offset within the selected store, with the store bit removed.
    pub fn within_store(self) -> u32 {
        self.0 & !STORE_BIT
    }

    /// Whether this is the format's "no cell" marker.
    ///
    /// A key with no subkeys stores `0xFFFFFFFF` in `SubKeyLists`, and
    /// translating it would be a lookup for a bin two gigabytes into the hive.
    pub fn is_nil(self) -> bool {
        self.0 == HCELL_NIL
    }

    /// This index advanced by `delta` bytes, staying inside the same store.
    ///
    /// # Errors
    ///
    /// [`RegistryError::Overflow`] if the sum would cross out of the store.
    pub fn offset_by(self, delta: u64) -> Result<CellIndex, RegistryError> {
        let within = u64::from(self.within_store())
            .checked_add(delta)
            .ok_or_else(|| {
                RegistryError::Overflow(format!(
                    "cell index {:#010x} plus {delta} does not fit in 64 bits",
                    self.0
                ))
            })?;
        if within > u64::from(!STORE_BIT) {
            return Err(RegistryError::Overflow(format!(
                "cell index {:#010x} plus {delta} runs out of the {} store and into the other one",
                self.0,
                self.store().as_str()
            )));
        }
        let store_bit = self.0 & STORE_BIT;
        Ok(CellIndex(store_bit | (within as u32)))
    }

    /// Index into `_HMAP_DIRECTORY.Directory`, from bits 30..21.
    pub fn directory_index(self) -> u64 {
        u64::from((self.within_store() >> DIRECTORY_SHIFT) & DIRECTORY_MASK)
    }

    /// Index into `_HMAP_TABLE.Table`, from bits 20..12.
    pub fn table_index(self) -> u64 {
        u64::from((self.within_store() >> TABLE_SHIFT) & TABLE_MASK)
    }

    /// Offset inside the 4 KiB page the `_HMAP_ENTRY` names, from bits 11..0.
    pub fn page_offset(self) -> u64 {
        u64::from(self.within_store() & PAGE_MASK)
    }
}

impl std::fmt::Display for CellIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

/// Where a cell index lands in the layer the bins live in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellLocation {
    /// The address in the bins layer.
    pub address: u64,
    /// How many bytes are contiguous from `address` — to the end of the mapped
    /// page, or to the end of the store, whichever comes first.
    ///
    /// Never assumed to be the whole of a caller's request: two consecutive
    /// pages of one hive bin can be anywhere relative to each other in memory,
    /// so a read that crosses a page boundary must translate again.
    pub run: u64,
}

/// First Windows 10 build that maps hive bins through the *Registry* process
/// rather than into paged pool.
///
/// Before it, `_HMAP_ENTRY.BlockAddress` is a kernel virtual address and the
/// kernel's own space reads it. From it, the address is only meaningful in the
/// Registry process, and reading it in kernel space returns a hole — an honest
/// one, but a hole where the evidence is.
pub const FIRST_REGISTRY_PROCESS_BUILD: u32 = 17063;

/// The image name of the minimal process the kernel maps hive bins through.
pub const REGISTRY_IMAGE_NAME: &str = "Registry";

/// Where a hive's bins were read from, and whether that is the right place for
/// this build.
///
/// Carried onto the hive and into its layer metadata because it decides what an
/// unreadable cell means. A hole in a hive opened against the kernel's space on
/// Windows 10 1709 or later is very likely the tool looking in the wrong place;
/// the same hole against the Registry process is a page that was never
/// captured. Rendering the two the same way would have an examiner conclude a
/// key was absent from the registry when it was merely unread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinSource {
    /// The kernel's own address space, which is where bins live up to and
    /// including Windows 10 1703.
    KernelPool,
    /// The Registry process's address space, from build 17063 on.
    RegistryProcess {
        /// The `_EPROCESS` the space was built from.
        process: u64,
        /// Its process id, when the list could read one.
        pid: Option<u64>,
    },
    /// This build maps bins through the Registry process and that process could
    /// not be reached, so the kernel's space was used instead.
    ///
    /// Reads then return holes rather than wrong bytes, which is the right
    /// failure — but it is a failure, and this is what says so.
    KernelPoolFallback {
        /// Why the Registry process could not be used.
        detail: String,
    },
    /// A layer the caller asserted is where this image's bins live.
    Supplied,
}

impl BinSource {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            BinSource::KernelPool => "kernel_pool",
            BinSource::RegistryProcess { .. } => "registry_process",
            BinSource::KernelPoolFallback { .. } => "kernel_pool_fallback",
            BinSource::Supplied => "supplied",
        }
    }

    /// Whether the bins were read from where this build actually keeps them.
    ///
    /// False means every unreadable cell is unexplained: the read may have
    /// failed because the page was never captured, or because it was looked for
    /// in the wrong address space, and this hive cannot tell the two apart.
    pub fn is_authoritative(&self) -> bool {
        !matches!(self, BinSource::KernelPoolFallback { .. })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            BinSource::RegistryProcess { process, pid } => serde_json::json!({
                "kind": self.as_str(),
                "process": process,
                "pid": pid,
                "authoritative": true,
            }),
            BinSource::KernelPoolFallback { detail } => serde_json::json!({
                "kind": self.as_str(),
                "detail": detail,
                "authoritative": false,
            }),
            other => serde_json::json!({"kind": other.as_str(), "authoritative": true}),
        }
    }
}

/// The address space this image's hive bins are read from.
#[derive(Clone)]
pub struct BinSpace {
    layer: Arc<dyn MemoryLayer>,
    source: BinSource,
}

impl std::fmt::Debug for BinSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinSpace")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl BinSpace {
    /// The layer bin pages are read from.
    pub fn layer(&self) -> &Arc<dyn MemoryLayer> {
        &self.layer
    }

    /// Where those pages came from.
    pub fn source(&self) -> &BinSource {
        &self.source
    }
}

/// Decide where this image's hive bins live, and open that space.
///
/// Cheap on every build before 17063: the answer is the kernel's own space and
/// nothing is walked to establish it. From 17063 the active process list is
/// walked to find the Registry process, so a caller opening many hives should
/// call this once and pass the result to
/// [`HiveSpace::open_with_bin_space`] rather than opening each hive with
/// [`HiveSpace::open_for_image`].
///
/// # What an examiner learns
///
/// Whether the hives in this image were read from where the kernel keeps them.
/// A modern image whose Registry process could not be found yields hives whose
/// cells are mostly unreadable, and [`BinSource::KernelPoolFallback`] is what
/// stops that reading as a registry that was mostly empty.
///
/// Never an error: every failure to find the Registry process leaves the
/// kernel's space in place, which produces holes rather than wrong bytes, and
/// records why.
pub fn locate_bin_space(profile: &WindowsProfile) -> BinSpace {
    let kernel = |source: BinSource| BinSpace {
        layer: Arc::clone(&profile.kernel_space),
        source,
    };

    let Some(build) = profile.build.build else {
        return kernel(BinSource::KernelPoolFallback {
            detail: "the Windows build number was never established, so it cannot be decided \
                     whether this image maps hive bins into paged pool or through the Registry \
                     process; the kernel's space was used and a cell it cannot reach may simply \
                     be in the other one"
                .to_string(),
        });
    };
    if build < FIRST_REGISTRY_PROCESS_BUILD {
        return kernel(BinSource::KernelPool);
    }

    let symbols = match crate::process::ProcessSymbols::from_profile(profile) {
        Ok(symbols) => symbols,
        Err(err) => {
            return kernel(BinSource::KernelPoolFallback {
                detail: format!(
                    "this build maps hive bins through the {REGISTRY_IMAGE_NAME} process and the \
                     process list cannot be described on it, so that process could not be found: \
                     {err}"
                ),
            })
        }
    };
    let list = match crate::process::list_processes(
        profile,
        &symbols,
        &crate::process::ProcessListConfig::default(),
    ) {
        Ok(list) => list,
        Err(err) => {
            return kernel(BinSource::KernelPoolFallback {
                detail: format!(
                    "this build maps hive bins through the {REGISTRY_IMAGE_NAME} process and the \
                     active process list could not be walked to find it: {err}"
                ),
            })
        }
    };

    let found = list.processes.iter().find(|record| {
        record
            .image_file_name
            .known()
            .is_some_and(|name| name.eq_ignore_ascii_case(REGISTRY_IMAGE_NAME))
    });
    let Some(record) = found else {
        return kernel(BinSource::KernelPoolFallback {
            detail: format!(
                "no process on the active list is named {REGISTRY_IMAGE_NAME}, so the space this \
                 build maps hive bins through could not be opened{}",
                if list.is_complete() {
                    ""
                } else {
                    " — and the list itself did not run to its end, so this is not evidence that \
                     the process was not running"
                }
            ),
        });
    };

    let cache = Arc::new(TableCache::new());
    match crate::process::process_address_space(profile, &symbols, record.address, &cache) {
        Ok(layer) => BinSpace {
            layer,
            source: BinSource::RegistryProcess {
                process: record.address,
                pid: record.pid.known().copied(),
            },
        },
        Err(err) => kernel(BinSource::KernelPoolFallback {
            detail: format!(
                "the {REGISTRY_IMAGE_NAME} process at {:#x} has no readable address space, so the \
                 hive bins this build maps through it could not be reached: {err}",
                record.address
            ),
        }),
    }
}

/// One store's length and storage map, read once when the hive is opened.
#[derive(Debug, Clone, Copy)]
struct StoreMap {
    /// `_DUAL.Length`: how far this store runs, in hive-space bytes.
    length: u64,
    /// `_DUAL.Map`: the `_HMAP_DIRECTORY`, or 0 when the store is empty.
    map: u64,
}

/// A single registry hive as an address space.
///
/// Reads are addressed by cell index and translated through the hive's own
/// storage map. Implements [`MemoryLayer`], so everything Séance already has —
/// the struct reader, the search indexer, the hasher, the content resolver —
/// composes with a hive recovered from RAM with no registry-specific plumbing.
#[derive(Debug)]
pub struct HiveSpace {
    /// Address of the `_CMHIVE` this space belongs to.
    cmhive: u64,
    /// Where the bins' bytes are read from.
    bins: Arc<dyn MemoryLayer>,
    /// Reader for the `_CMHIVE` and its storage map, in kernel space.
    kernel: StructReader,
    /// Per-store length and map pointer.
    stores: [StoreMap; 2],
    /// Bytes of allocation header in front of every cell.
    cell_header: u64,
    /// Where the bins were read from, and whether that is where this build
    /// keeps them.
    bin_source: BinSource,
    /// Layer metadata, parented to the layer the bins came from.
    meta: LayerMeta,
}

impl HiveSpace {
    /// Open the hive at `cmhive`, reading its bins from the kernel address
    /// space.
    ///
    /// # Errors
    ///
    /// [`RegistryError::HiveSignature`] if the structure is not a hive, and
    /// [`RegistryError::Obj`] if the symbol table does not describe `_CMHIVE`,
    /// `_HHIVE`, `_DUAL` or `_HMAP_*` for this build, or if the hive header's
    /// bytes were never acquired. Nothing is defaulted: a hive whose
    /// `_DUAL.Length` could not be read has an unknown extent, and an unknown
    /// extent means every cell index would be checked against a number that was
    /// invented.
    pub fn open(profile: &WindowsProfile, cmhive: u64) -> Result<Arc<HiveSpace>, RegistryError> {
        let bins = Arc::clone(&profile.kernel_space);
        HiveSpace::open_inner(profile, cmhive, bins, BinSource::KernelPool)
    }

    /// Open the hive at `cmhive` from wherever this image keeps its bins.
    ///
    /// The production entry point. On Windows 10 1703 and earlier this is
    /// [`HiveSpace::open`]; from build 17063 it finds the Registry process and
    /// reads the bins through it, which is the difference between a hive whose
    /// cells read and one whose cells are almost entirely holes.
    ///
    /// Finding that process costs one process-list walk, so a caller opening
    /// several hives should call [`locate_bin_space`] once and use
    /// [`HiveSpace::open_with_bin_space`].
    ///
    /// # Errors
    ///
    /// As [`HiveSpace::open`]. A Registry process that could not be found is
    /// **not** an error: the kernel's space is used, and
    /// [`HiveSpace::bin_source`] says the hive's holes are unexplained.
    pub fn open_for_image(
        profile: &WindowsProfile,
        cmhive: u64,
    ) -> Result<Arc<HiveSpace>, RegistryError> {
        HiveSpace::open_with_bin_space(profile, cmhive, &locate_bin_space(profile))
    }

    /// Open the hive at `cmhive` using a bin space located once for the image.
    pub fn open_with_bin_space(
        profile: &WindowsProfile,
        cmhive: u64,
        bins: &BinSpace,
    ) -> Result<Arc<HiveSpace>, RegistryError> {
        HiveSpace::open_inner(
            profile,
            cmhive,
            Arc::clone(bins.layer()),
            bins.source().clone(),
        )
    }

    /// Open the hive at `cmhive`, reading its bins from `bins`.
    ///
    /// For a caller that already holds the Registry process's address space, or
    /// for fixtures. The `_CMHIVE` and the storage map are still read from the
    /// kernel space in the profile, which is where they live on every build.
    pub fn open_with_bins(
        profile: &WindowsProfile,
        cmhive: u64,
        bins: Arc<dyn MemoryLayer>,
    ) -> Result<Arc<HiveSpace>, RegistryError> {
        HiveSpace::open_inner(profile, cmhive, bins, BinSource::Supplied)
    }

    fn open_inner(
        profile: &WindowsProfile,
        cmhive: u64,
        bins: Arc<dyn MemoryLayer>,
        bin_source: BinSource,
    ) -> Result<Arc<HiveSpace>, RegistryError> {
        let kernel = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let cell_header = cell_header_len(&profile.symbols)?;

        let hive = kernel.object(cmhive, "_CMHIVE")?.embedded("Hive")?;
        let signature = unsigned_member(&hive, "Signature")?;
        if signature != HIVE_SIGNATURE {
            return Err(RegistryError::HiveSignature {
                address: cmhive,
                found: signature,
                expected: HIVE_SIGNATURE,
            });
        }

        let mut stores = [StoreMap { length: 0, map: 0 }; 2];
        for store in [Store::Stable, Store::Volatile] {
            let dual = hive.element_object("Storage", store.slot())?;
            stores[store.slot() as usize] = StoreMap {
                length: unsigned_member(&dual, "Length")?,
                map: dual.pointer("Map")?,
            };
        }

        let meta = LayerMeta::default()
            .with_parent(Arc::new(bins.layer_meta().clone()))
            .with_note("registry_hive", cmhive)
            .with_note("stable_length", stores[0].length)
            .with_note("volatile_length", stores[1].length)
            .with_note("bin_source", bin_source.as_str())
            .with_note("bin_source_authoritative", bin_source.is_authoritative());

        Ok(Arc::new(HiveSpace {
            cmhive,
            bins,
            kernel,
            stores,
            cell_header,
            bin_source,
            meta,
        }))
    }

    /// Where this hive's bins were read from.
    ///
    /// A report quoting a key from a hive whose source is not authoritative has
    /// to say so: the cells that did not read may be in an address space the
    /// tool never looked at.
    pub fn bin_source(&self) -> &BinSource {
        &self.bin_source
    }

    /// Address of the `_CMHIVE` this space belongs to.
    ///
    /// The provenance an examiner needs beside every key: two hives' cell
    /// indices are unrelated, so a key path means nothing without it.
    pub fn cmhive_address(&self) -> u64 {
        self.cmhive
    }

    /// Bytes of allocation header in front of every cell.
    pub fn cell_header_len(&self) -> u64 {
        self.cell_header
    }

    /// The declared length of one store, in hive-space bytes.
    pub fn store_length(&self, store: Store) -> u64 {
        self.stores[store.slot() as usize].length
    }

    /// A reader for structures *inside* the hive, addressed by cell index.
    ///
    /// Separate from the kernel-space reader the hive header was read through,
    /// because a `_CM_KEY_NODE` lives at a cell index and an `_HMAP_ENTRY` lives
    /// at a kernel virtual address, and the two spaces have nothing to do with
    /// each other.
    pub fn cell_reader(hive: &Arc<HiveSpace>) -> StructReader {
        // Name the concrete type so `Arc::clone` is not asked to produce the
        // trait object directly; the unsizing coercion happens on assignment.
        let layer: Arc<dyn MemoryLayer> = Arc::<HiveSpace>::clone(hive);
        StructReader::new(layer, Arc::clone(hive.kernel.symbols()))
    }

    /// The symbol table this hive is read through.
    pub fn symbols(&self) -> &Arc<SymbolTable> {
        self.kernel.symbols()
    }

    /// `_HHIVE.Version`: the hive format's minor version, normally 3, 4 or 5.
    pub fn version(&self) -> Result<u64, RegistryError> {
        let hive = self
            .kernel
            .object(self.cmhive, "_CMHIVE")?
            .embedded("Hive")?;
        unsigned_member(&hive, "Version")
    }

    /// The root key's cell index, and how it was established.
    ///
    /// Taken from `_HBASE_BLOCK.RootCell` when the base block is readable and
    /// carries the `regf` signature — that is the hive stating its own root, and
    /// it is [`Evidence::Confirmed`].
    ///
    /// When the base block was paged out, the fallback is **not** to assume the
    /// format's usual `0x20`. It is to *test* `0x20`: read the two bytes a key
    /// node starts with, and accept the candidate only if they are `nk`. That is
    /// [`Evidence::Validated`] — weaker than the hive's own statement, and
    /// recorded as such, so a report can say which one this tree rests on.
    ///
    /// # Errors
    ///
    /// If neither holds. A hive whose root cannot be established yields no keys
    /// at all rather than a tree rooted on a guess.
    pub fn root_cell(&self) -> Result<Found<CellIndex>, RegistryError> {
        let base_block_failure = match self.base_block_root() {
            Ok(Some(root)) => {
                return Ok(Found::new(CellIndex::new(root), Evidence::Confirmed));
            }
            Ok(None) => "the base block does not carry the 'regf' signature".to_string(),
            Err(err) => err.to_string(),
        };

        let probe = CellIndex::new(PROBE_ROOT_CELL);
        // A cell index names the cell's *allocation header*; the two letters that
        // say what the cell is start [`CELL_HEADER_LEN`] bytes later. Probing at
        // the index itself reads the low half of the allocation size, which is
        // never `nk`, so the fallback would refuse every hive it exists for.
        let contents = probe.offset_by(self.cell_header)?;
        match self.read_cell(contents, 2) {
            Ok(bytes) if bytes.as_slice() == b"nk".as_slice() => {
                Ok(Found::new(probe, Evidence::Validated))
            }
            Ok(bytes) => Err(RegistryError::Malformed(format!(
                "{base_block_failure}, and cell {probe} begins with {}, not a key node, so this \
                 hive's root cell cannot be established",
                crate::registry::error::render_signature([bytes[0], bytes[1]])
            ))),
            Err(err) => Err(RegistryError::Malformed(format!(
                "{base_block_failure}, and cell {probe} could not be read either ({err}), so this \
                 hive's root cell cannot be established"
            ))),
        }
    }

    /// `_HBASE_BLOCK.RootCell`, or `None` if the block is not a `regf` block.
    fn base_block_root(&self) -> Result<Option<u32>, RegistryError> {
        let hive = self
            .kernel
            .object(self.cmhive, "_CMHIVE")?
            .embedded("Hive")?;
        let Some(base_block) = hive.follow("BaseBlock")? else {
            return Err(RegistryError::Malformed(format!(
                "the hive at {:#x} has a null _HHIVE.BaseBlock",
                self.cmhive
            )));
        };
        if unsigned_member(&base_block, "Signature")? != HBASE_SIGNATURE {
            return Ok(None);
        }
        let root = unsigned_member(&base_block, "RootCell")?;
        u32::try_from(root).map(Some).map_err(|_| {
            RegistryError::Malformed(format!(
                "the base block of the hive at {:#x} declares the root cell {root:#x}, which is \
                 not a 32-bit cell index",
                self.cmhive
            ))
        })
    }

    /// Translate one cell index to an address in the bins layer.
    ///
    /// # Errors
    ///
    /// [`RegistryError::CellOutOfRange`] when the index is past the end of the
    /// store it selects, and [`RegistryError::UnmappedCell`] when the storage
    /// map has no bin for it. Neither is treated as an empty page: a cell index
    /// the hive cannot place is a cell index that must not be read.
    pub fn translate(&self, index: CellIndex) -> Result<CellLocation, RegistryError> {
        let store = index.store();
        let map = self.stores[store.slot() as usize];
        let within = u64::from(index.within_store());
        if within >= map.length {
            return Err(RegistryError::CellOutOfRange {
                index: index.raw(),
                store: store.as_str(),
                length: map.length,
                past: within.saturating_sub(map.length).saturating_add(1),
            });
        }
        if map.map == 0 {
            return Err(RegistryError::UnmappedCell {
                index: index.raw(),
                detail: format!("the {} store has a null _DUAL.Map", store.as_str()),
            });
        }

        let directory = self.kernel.object(map.map, "_HMAP_DIRECTORY")?;
        let table_pointer = as_address(
            directory.element_int("Directory", index.directory_index())?,
            "_HMAP_DIRECTORY.Directory",
        )?;
        if table_pointer == 0 {
            return Err(RegistryError::UnmappedCell {
                index: index.raw(),
                detail: format!(
                    "_HMAP_DIRECTORY.Directory[{}] of the {} store is null",
                    index.directory_index(),
                    store.as_str()
                ),
            });
        }

        let table = self.kernel.object(table_pointer, "_HMAP_TABLE")?;
        let entry = table.element_object("Table", index.table_index())?;
        let block = block_address(&entry)?;
        if block == 0 {
            return Err(RegistryError::UnmappedCell {
                index: index.raw(),
                detail: format!(
                    "the _HMAP_ENTRY for _HMAP_TABLE[{}] of the {} store names no bin",
                    index.table_index(),
                    store.as_str()
                ),
            });
        }

        let page_offset = index.page_offset();
        let address = block.checked_add(page_offset).ok_or_else(|| {
            RegistryError::Overflow(format!(
                "the bin at {block:#x} plus {page_offset} does not fit in 64 bits"
            ))
        })?;
        let to_page_end = HIVE_PAGE_SIZE.saturating_sub(page_offset);
        let to_store_end = map.length.saturating_sub(within);
        Ok(CellLocation {
            address,
            run: to_page_end.min(to_store_end),
        })
    }

    /// Read `len` bytes starting at a cell index.
    ///
    /// Crosses page boundaries by translating again, because two consecutive
    /// pages of one bin are not consecutive in memory.
    ///
    /// # Errors
    ///
    /// The first failure, with nothing returned: a value made of the pages that
    /// were resident and zeros for the ones that were not is not the value the
    /// suspect's machine held.
    pub fn read_cell(&self, index: CellIndex, len: u64) -> Result<Vec<u8>, RegistryError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        if len > MAX_CELL_READ {
            return Err(RegistryError::Cap {
                what: "a single read out of a registry hive",
                cap: MAX_CELL_READ,
            });
        }
        let mut buf = vec![0u8; len as usize];
        let (filled, failure) = self.fill(index, &mut buf);
        match failure {
            Some(err) if filled < buf.len() => Err(err),
            _ => Ok(buf),
        }
    }

    /// Fill as much of `buf` as the hive can supply, reporting what stopped it.
    ///
    /// The two-value return is what lets the typed API fail closed while the
    /// [`MemoryLayer`] implementation honours the `DataSource` contract of
    /// returning short reads rather than errors once it has made progress.
    fn fill(&self, index: CellIndex, buf: &mut [u8]) -> (usize, Option<RegistryError>) {
        let mut filled = 0usize;
        while filled < buf.len() {
            let remaining = (buf.len() - filled) as u64;
            let at = match index.offset_by(filled as u64) {
                Ok(at) => at,
                Err(err) => return (filled, Some(err)),
            };
            let location = match self.translate(at) {
                Ok(location) => location,
                Err(err) => return (filled, Some(err)),
            };
            let chunk = remaining.min(location.run) as usize;
            if chunk == 0 {
                return (
                    filled,
                    Some(RegistryError::Malformed(format!(
                        "the storage map placed cell {at} in a run of zero bytes"
                    ))),
                );
            }
            let end = filled + chunk;
            if let Err(err) = read_exact_or_fail(
                self.bins.as_data_source(),
                location.address,
                &mut buf[filled..end],
                "a registry hive bin",
            ) {
                let obj =
                    ObjError::from_read(location.address, chunk as u64, "a registry hive bin", err);
                return (filled, Some(RegistryError::Obj(obj)));
            }
            filled = end;
        }
        (filled, None)
    }

    /// Highest addressable cell index, as an address in this layer.
    ///
    /// `0x80000000 | volatile length`: the volatile store is addressed above the
    /// store bit, so the span of the space has to reach over it. The stable
    /// store's own extent is [`HiveSpace::store_length`]; the range between the
    /// two is inside the span and has nothing behind it, which is exactly what a
    /// hole is for.
    fn top_address(&self) -> u64 {
        u64::from(STORE_BIT) | self.stores[1].length
    }
}

impl seance_core::data_source::DataSource for HiveSpace {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let top = self.top_address();
        if offset > top {
            // Above the top of the space is genuine end-of-data, not a hole.
            return Ok(0);
        }
        let Ok(raw) = u32::try_from(offset) else {
            return Ok(0);
        };
        let available = top.saturating_sub(offset).saturating_add(1);
        let want = (buf.len() as u64).min(available) as usize;
        let (filled, failure) = self.fill(CellIndex::new(raw), &mut buf[..want]);
        match failure {
            // Progress already made: report it, and let the caller come back for
            // the rest and meet the same failure with nothing in the way.
            Some(_) if filled > 0 => Ok(filled),
            Some(err) => Err(registry_error_to_io(offset, want as u64, err)),
            None => Ok(filled),
        }
    }

    fn size(&self) -> u64 {
        self.top_address().saturating_add(1)
    }
}

impl MemoryLayer for HiveSpace {
    fn min_address(&self) -> u64 {
        0
    }

    fn max_address(&self) -> u64 {
        self.top_address()
    }

    fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError> {
        let top = self.top_address();
        if offset > top {
            return Err(LayerError::OutOfRange {
                address: offset,
                max_address: top,
            });
        }
        let available = top.saturating_sub(offset).saturating_add(1);
        let mut remaining = length.min(available);
        let mut runs: Vec<MappedRange> = Vec::new();
        let mut at = offset;
        while remaining > 0 {
            let Ok(raw) = u32::try_from(at) else {
                return Err(LayerError::Hole(MemoryHole::unmapped(at, remaining)));
            };
            let index = CellIndex::new(raw);
            let location = self
                .translate(index)
                .map_err(|err| translation_to_layer_error(at, remaining, err))?;
            let run = remaining.min(location.run);
            if run == 0 {
                return Err(LayerError::Hole(MemoryHole::unmapped(at, remaining)));
            }
            runs.push(MappedRange::identity(at, run, location.address));
            at = at.saturating_add(run);
            remaining -= run;
        }
        Ok(runs)
    }

    fn layer_meta(&self) -> &LayerMeta {
        &self.meta
    }

    fn as_data_source(&self) -> &dyn seance_core::data_source::DataSource {
        self
    }
}

/// Turn a translation failure into the layer vocabulary.
///
/// Everything the hive cannot place is a hole *in the hive's address space*,
/// whatever the reason underneath: there is an address, and there are no bytes
/// behind it. A hole from the layer below is passed through unchanged so the
/// range it names survives.
fn translation_to_layer_error(offset: u64, length: u64, err: RegistryError) -> LayerError {
    match err.hole() {
        Some(hole) => LayerError::Hole(hole),
        None => LayerError::Hole(MemoryHole::unmapped(offset, length)),
    }
}

/// Turn a registry failure into an `io::Error` that keeps its hole.
fn registry_error_to_io(offset: u64, length: u64, err: RegistryError) -> std::io::Error {
    match err.hole() {
        Some(hole) => hole.into_io(),
        None => MemoryHole::unmapped(offset, length.max(1)).into_io(),
    }
}

/// Read a member that must hold a non-negative number: an address, a length or
/// a count.
///
/// Accepts whichever signedness the symbol table declares and refuses a
/// negative value, rather than reinterpreting its bits. A `_DUAL.Length` of
/// `-1` read as `0xFFFFFFFFFFFFFFFF` would make every cell index in the image
/// look in range.
pub(crate) fn unsigned_member(obj: &Obj, path: &str) -> Result<u64, RegistryError> {
    match obj.int(path)? {
        IntValue::Unsigned(value) => Ok(value),
        IntValue::Signed(value) => u64::try_from(value).map_err(|_| {
            RegistryError::Malformed(format!(
                "'{}.{path}' holds {value}, and a negative number cannot be an address, a length \
                 or a count",
                obj.type_name()
            ))
        }),
    }
}

/// An array element that is being used as an address.
fn as_address(value: IntValue, what: &str) -> Result<u64, RegistryError> {
    value.as_u64().ok_or_else(|| {
        RegistryError::Malformed(format!(
            "'{what}' holds {value}, and a negative number cannot be an address"
        ))
    })
}

/// The bin address an `_HMAP_ENTRY` names.
///
/// The structure changed shape at Windows 8: before it, one `BlockAddress`
/// field held the address outright; from Windows 8 the entry holds the bin's
/// address with four flag bits in the bottom of it, plus the block's offset
/// inside that bin. Which shape this build uses is asked of the symbol table,
/// never assumed from the build number, and a table describing neither is an
/// error naming both — because picking one would produce an address that is
/// wrong by a bin and reads back as a perfectly well-formed cell.
fn block_address(entry: &Obj) -> Result<u64, RegistryError> {
    if entry.has_member("PermanentBinAddress") {
        let bin = unsigned_member(entry, "PermanentBinAddress")?;
        let offset = unsigned_member(entry, "BlockOffset")?;
        return (bin & !0xF).checked_add(offset).ok_or_else(|| {
            RegistryError::Overflow(format!(
                "the bin at {bin:#x} plus the block offset {offset:#x} does not fit in 64 bits"
            ))
        });
    }
    if entry.has_member("BlockAddress") {
        return unsigned_member(entry, "BlockAddress");
    }
    Err(RegistryError::from(SymbolError::UnknownMember {
        type_name: entry.type_name().to_string(),
        member: "PermanentBinAddress (Windows 8 and later) or BlockAddress (earlier)".to_string(),
    }))
}

/// Bytes of allocation header in front of every cell, cross-checked against the
/// symbol table.
///
/// [`CELL_HEADER_LEN`] is a property of the hive file format rather than of the
/// running kernel, and kernel symbol tables normally do not describe `_HCELL` at
/// all. When one does, its layout must agree: a table that put the cell's
/// contents somewhere else would mean every structure in this module is read
/// from the wrong offset, and a `_CM_KEY_NODE` read four bytes early still has a
/// plausible name in it.
///
/// # What absence means here, and why it is not a failure
///
/// The cross-check is available or it is not; the answer does not depend on it.
/// A table with no `_HCELL` cannot be cross-checked, and a table whose `_HCELL`
/// declares no `u` member cannot be cross-checked either — the two are the same
/// state, and only the first used to be treated that way. The second failed the
/// whole registry stage over a member whose only use is to confirm a constant
/// that the hive file format fixes, which is the Vista-member-on-XP shape
/// exactly: a build-variant member proved fatally where nothing reads it.
///
/// A table that *cannot answer* — a name it declares twice and refuses to
/// disambiguate — is still an error, because that is a symbol table this
/// analysis could not read rather than a statement about the machine.
pub fn cell_header_len(symbols: &SymbolTable) -> Result<u64, RegistryError> {
    if !symbols.has_type("_HCELL") {
        return Ok(CELL_HEADER_LEN);
    }
    let Some(contents) = first_declared_member(symbols, "_HCELL", &["u"])? else {
        return Ok(CELL_HEADER_LEN);
    };
    let declared = symbols.member_offset("_HCELL", contents)?;
    if declared != CELL_HEADER_LEN {
        return Err(RegistryError::Malformed(format!(
            "this symbol table places the contents of a registry cell at offset {declared} inside \
             '_HCELL', and the hive file format puts them at {CELL_HEADER_LEN}"
        )));
    }
    Ok(CELL_HEADER_LEN)
}

/// The type of a member reached by a `.`-separated path through embedded
/// aggregates.
///
/// The object model resolves such a path to an *offset*; this resolves it to
/// the *type*, which is what a caller needs to ask how wide an element of an
/// array member is. Never dereferences a pointer, for the same reason the
/// object model does not: a hidden read is a read an examiner cannot account
/// for.
pub fn member_type(
    symbols: &SymbolTable,
    type_name: &str,
    path: &str,
) -> Result<TypeId, RegistryError> {
    let mut current = symbols.type_id(type_name)?;
    let mut current_name = type_name.to_string();
    for segment in path.split('.') {
        let aggregate = match &symbols.entry(current)?.kind {
            TypeKind::Aggregate(info) => info,
            other => {
                return Err(RegistryError::from(SymbolError::WrongTypeKind {
                    name: current_name,
                    actual: other.as_str(),
                    expected: "a struct, union or class",
                }))
            }
        };
        let member = aggregate
            .member(segment)
            .ok_or_else(|| SymbolError::UnknownMember {
                type_name: current_name.clone(),
                member: segment.to_string(),
            })?;
        current = member.ty;
        current_name = symbols.entry(current)?.name.to_string();
    }
    Ok(current)
}

/// Element width and declared count of an array member.
///
/// Both come from the symbol table. The registry's cell-index arrays are all
/// declared with a count of one and used with a count read out of the image —
/// that is how the format works — so the count here is only ever a sanity
/// bound, and the *width* is the number that matters: a stride of eight over an
/// array of four-byte cell indices reads every other entry and reports half a
/// registry.
pub fn array_shape(
    symbols: &SymbolTable,
    type_name: &str,
    path: &str,
) -> Result<(u64, u64), RegistryError> {
    let id = member_type(symbols, type_name, path)?;
    match &symbols.entry(id)?.kind {
        TypeKind::Array { subtype, count } => Ok((symbols.size_of_id(*subtype)?, *count)),
        other => Err(RegistryError::from(SymbolError::WrongTypeKind {
            name: format!("{type_name}.{path}"),
            actual: other.as_str(),
            expected: "an array member",
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::test_support::{
        hcell_table_without_contents, hcell_tables, win8_profile, xp_profile, PAGED_OUT_CELL,
        ROOT_CELL, STABLE_LENGTH, VOLATILE_BIN_VA, VOLATILE_LENGTH, WIN8_BIN_VA, WIN8_CMHIVE,
        WIN8_ROOT_CELL, XP_CMHIVE, XP_STABLE_BIN_VA, XP_UNNAMED_CMHIVE,
    };
    use seance_core::io::IncompleteReason;

    #[test]
    fn bit_thirty_one_of_a_cell_index_selects_the_store_and_nothing_else_does() {
        let stable = CellIndex::new(0x0000_1234);
        let volatile = CellIndex::new(0x8000_1234);
        assert_eq!(stable.store(), Store::Stable);
        assert_eq!(volatile.store(), Store::Volatile);
        assert_eq!(
            stable.within_store(),
            volatile.within_store(),
            "the two stores use the same offsets; only the bit tells them apart"
        );
        assert_eq!(stable.store().as_str(), "stable");
        assert_eq!(volatile.store().as_str(), "volatile");
        assert_eq!(volatile.store().slot(), 1);
    }

    #[test]
    fn the_map_indices_come_from_the_documented_bit_positions() {
        // 0x00A0_3456: directory 0b00000_00101 = 5, table 0b0_0011 0100 -> 0x34,
        // page offset 0x456.
        let index = CellIndex::new((5 << 21) | (0x34 << 12) | 0x456);
        assert_eq!(index.directory_index(), 5);
        assert_eq!(index.table_index(), 0x34);
        assert_eq!(index.page_offset(), 0x456);

        // And the store bit never leaks into any of them.
        let volatile = CellIndex::new(index.raw() | STORE_BIT);
        assert_eq!(volatile.directory_index(), 5);
        assert_eq!(volatile.table_index(), 0x34);
        assert_eq!(volatile.page_offset(), 0x456);
    }

    #[test]
    fn advancing_a_cell_index_never_crosses_into_the_other_store() {
        let last = CellIndex::new(0x7FFF_FFFC);
        assert_eq!(last.offset_by(3).unwrap().raw(), 0x7FFF_FFFF);
        let err = last
            .offset_by(4)
            .expect_err("four bytes on from the last stable byte is not the first volatile one");
        assert_eq!(err.class(), "overflow");

        // The volatile store advances inside itself, keeping its bit.
        let volatile = CellIndex::new(STORE_BIT | 0x20);
        assert_eq!(volatile.offset_by(4).unwrap().raw(), STORE_BIT | 0x24);
    }

    #[test]
    fn the_no_cell_marker_is_recognised_rather_than_translated() {
        assert!(CellIndex::new(HCELL_NIL).is_nil());
        assert!(!CellIndex::new(0x20).is_nil());
    }

    // ── Where the bins live ─────────────────────────────────────────────────

    #[test]
    fn a_build_before_the_registry_process_reads_its_bins_from_the_kernel() {
        // Up to Windows 10 1703 the kernel maps hive bins into paged pool, so
        // nothing needs finding and no process list is walked.
        let profile = xp_profile();
        let bins = locate_bin_space(&profile);
        assert_eq!(*bins.source(), BinSource::KernelPool);
        assert!(bins.source().is_authoritative());
        assert!(Arc::ptr_eq(bins.layer(), &profile.kernel_space));
    }

    #[test]
    fn a_modern_build_with_no_registry_process_says_its_holes_are_unexplained() {
        // The failure this guards: opening a 17063-or-later hive against the
        // kernel's space and reporting the resulting holes as though the pages
        // had never been captured. They may simply be in the address space the
        // tool did not look in, and a report cannot tell the two apart unless
        // the hive says which happened.
        let mut profile = xp_profile();
        profile.build.build = Some(19041);
        let bins = locate_bin_space(&profile);
        match bins.source() {
            BinSource::KernelPoolFallback { detail } => {
                assert!(detail.contains(REGISTRY_IMAGE_NAME), "{detail}");
            }
            other => panic!("expected a stated fallback, got {other:?}"),
        }
        assert!(!bins.source().is_authoritative());
        assert_eq!(bins.source().to_json()["authoritative"], false);
        // The kernel's space is still used, so reads produce holes rather than
        // bytes from some other process's page tables.
        assert!(Arc::ptr_eq(bins.layer(), &profile.kernel_space));
    }

    #[test]
    fn an_image_whose_build_is_unknown_does_not_assume_where_its_bins_are() {
        let mut profile = xp_profile();
        profile.build.build = None;
        let bins = locate_bin_space(&profile);
        assert!(!bins.source().is_authoritative());
        assert!(matches!(
            bins.source(),
            BinSource::KernelPoolFallback { .. }
        ));
    }

    #[test]
    fn the_bin_source_travels_onto_the_hive_and_into_its_layer_metadata() {
        let profile = xp_profile();
        let hive = HiveSpace::open_for_image(&profile, XP_CMHIVE).expect("the fixture hive opens");
        assert_eq!(*hive.bin_source(), BinSource::KernelPool);
        assert_eq!(
            hive.layer_meta()
                .note("bin_source")
                .and_then(|v| v.as_str()),
            Some("kernel_pool")
        );
        assert_eq!(
            hive.layer_meta()
                .note("bin_source_authoritative")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        // And the hive itself is the same one the kernel-space open produces on
        // a build that keeps its bins there.
        assert_eq!(hive.store_length(Store::Stable), STABLE_LENGTH);
    }

    #[test]
    fn a_supplied_bin_layer_is_recorded_as_the_callers_assertion() {
        let profile = xp_profile();
        let hive =
            HiveSpace::open_with_bins(&profile, XP_CMHIVE, Arc::clone(&profile.kernel_space))
                .expect("the fixture hive opens");
        assert_eq!(*hive.bin_source(), BinSource::Supplied);
    }

    #[test]
    fn opening_a_hive_reads_both_store_lengths_from_the_image() {
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_CMHIVE).expect("the fixture hive opens");
        assert_eq!(hive.cmhive_address(), XP_CMHIVE);
        assert_eq!(hive.store_length(Store::Stable), STABLE_LENGTH);
        assert_eq!(hive.store_length(Store::Volatile), VOLATILE_LENGTH);
        assert_eq!(hive.cell_header_len(), CELL_HEADER_LEN);
        assert_eq!(hive.version().unwrap(), 5);
    }

    #[test]
    fn a_structure_without_the_hive_signature_is_refused_rather_than_parsed() {
        // The fixture puts a plausible-looking allocation that is not a hive at
        // a known address. Parsing it would attribute a whole key tree to it.
        let profile = xp_profile();
        let err = HiveSpace::open(&profile, XP_CMHIVE + 0x400)
            .expect_err("a structure with no hive signature must not open");
        assert_eq!(err.class(), "hive_signature");
        assert!(err.to_string().contains("0xbee0bee0"), "{err}");
    }

    #[test]
    fn a_stable_cell_index_translates_through_the_stable_map_only() {
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_CMHIVE).unwrap();
        let located = hive.translate(CellIndex::new(0x20)).unwrap();
        assert_eq!(located.address, XP_STABLE_BIN_VA + 0x20);
        assert_eq!(
            located.run,
            HIVE_PAGE_SIZE - 0x20,
            "a run stops at the end of the page, because the next page is elsewhere"
        );
    }

    #[test]
    fn the_same_offset_in_the_volatile_store_translates_somewhere_completely_different() {
        // The single most consequential bit in the module: read a volatile
        // index through the stable map and you get a different key that parses.
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_CMHIVE).unwrap();
        let stable = hive.translate(CellIndex::new(0x20)).unwrap();
        let volatile = hive.translate(CellIndex::new(STORE_BIT | 0x20)).unwrap();
        assert_eq!(volatile.address, VOLATILE_BIN_VA + 0x20);
        assert_ne!(stable.address, volatile.address);
    }

    #[test]
    fn a_cell_index_past_the_end_of_its_store_is_refused_and_says_by_how_much() {
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_CMHIVE).unwrap();
        let err = hive
            .translate(CellIndex::new(STABLE_LENGTH as u32 + 0x10))
            .expect_err("past the end of the store there is no cell");
        match err {
            RegistryError::CellOutOfRange {
                store,
                length,
                past,
                ..
            } => {
                assert_eq!(store, "stable");
                assert_eq!(length, STABLE_LENGTH);
                assert_eq!(past, 0x11);
            }
            other => panic!("expected an out-of-range cell, got {other}"),
        }
    }

    #[test]
    fn a_cell_whose_bin_was_never_acquired_is_a_hole_and_not_an_empty_cell() {
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_CMHIVE).unwrap();
        // The bin is mapped by the storage map; its bytes are in the image's
        // unacquired window.
        let err = hive
            .read_cell(CellIndex::new(PAGED_OUT_CELL), 16)
            .expect_err("an unacquired bin must not read as zeros");
        assert_eq!(err.incomplete_reason(), IncompleteReason::ShortRead);
        assert!(
            err.hole().is_some(),
            "the unmapped range must survive: {err}"
        );
    }

    #[test]
    fn a_read_that_crosses_a_page_boundary_translates_again_instead_of_running_on() {
        // Hive pages are contiguous in the hive's address space and scattered in
        // memory. The fixture puts page 1 well away from page 0, so a read that
        // ran straight on would return the wrong second half.
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_CMHIVE).unwrap();
        let bytes = hive
            .read_cell(CellIndex::new(0x0FFE), 4)
            .expect("the read spans the end of page 0 and the start of page 1");
        assert_eq!(bytes, vec![0xAA, 0xAA, 0xBB, 0xBB]);
    }

    #[test]
    fn an_oversized_read_is_capped_rather_than_allocated() {
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_CMHIVE).unwrap();
        let err = hive
            .read_cell(CellIndex::new(0x20), MAX_CELL_READ + 1)
            .expect_err("a length taken from a registry value must be bounded");
        assert_eq!(err.incomplete_reason(), IncompleteReason::CapReached);
    }

    #[test]
    fn the_root_cell_comes_from_the_hives_own_base_block_when_it_is_readable() {
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_CMHIVE).unwrap();
        let root = hive.root_cell().expect("the base block is resident");
        assert_eq!(root.value, CellIndex::new(ROOT_CELL));
        assert_eq!(root.evidence, Evidence::Confirmed);
    }

    #[test]
    fn a_hive_with_an_unreadable_base_block_validates_its_root_instead_of_assuming_one() {
        // The second fixture hive's BaseBlock points into the unacquired window.
        // Upstream would return 0x20 unconditionally; here 0x20 is a candidate
        // that has to look like a key node before it is believed, and the
        // weaker evidence is recorded.
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_UNNAMED_CMHIVE).unwrap();
        let root = hive.root_cell().expect("cell 0x20 is an 'nk' record");
        assert_eq!(root.value, CellIndex::new(PROBE_ROOT_CELL));
        assert_eq!(
            root.evidence,
            Evidence::Validated,
            "a probed root is weaker evidence than a hive stating its own"
        );
    }

    #[test]
    fn the_root_probe_looks_at_the_cells_contents_and_not_at_its_allocation_header() {
        // A cell index names the four-byte allocation size; the `nk` that says
        // what the cell is starts after it. Probing at the index itself reads the
        // low half of that size, which is never `nk`, so the whole fallback would
        // refuse every hive it exists for — and a hive with a paged-out base
        // block would yield no keys at all rather than a validated tree.
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_UNNAMED_CMHIVE).unwrap();

        let at_index = hive
            .read_cell(CellIndex::new(PROBE_ROOT_CELL), 2)
            .expect("the probe cell's bin is resident");
        assert_ne!(
            at_index.as_slice(),
            b"nk".as_slice(),
            "the bytes at the bare index must not be the signature, or this test proves nothing"
        );
        let at_contents = hive
            .read_cell(
                CellIndex::new(PROBE_ROOT_CELL)
                    .offset_by(CELL_HEADER_LEN)
                    .unwrap(),
                2,
            )
            .expect("the contents are resident too");
        assert_eq!(at_contents.as_slice(), b"nk".as_slice());

        assert_eq!(
            hive.root_cell().expect("the probe validates").evidence,
            Evidence::Validated
        );
    }

    #[test]
    fn a_hive_space_is_a_memory_layer_the_rest_of_seance_can_read_through() {
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_CMHIVE).unwrap();
        let layer: Arc<dyn MemoryLayer> = Arc::<HiveSpace>::clone(&hive);

        assert_eq!(layer.min_address(), 0);
        assert_eq!(layer.max_address(), u64::from(STORE_BIT) | VOLATILE_LENGTH);

        let mut buf = [0u8; 2];
        read_exact_or_fail(
            layer.as_data_source(),
            u64::from(ROOT_CELL) + 4,
            &mut buf,
            "nk",
        )
        .expect("the root key node is resident");
        assert_eq!(&buf, b"nk");

        let runs = layer.mapping(0x20, 0x10).expect("a mapped cell projects");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].mapped_offset, XP_STABLE_BIN_VA + 0x20);
        assert_eq!(runs[0].length, 0x10);

        // The gap between the top of the stable store and the store bit is
        // inside the span of the space and has nothing behind it.
        assert!(!layer.is_valid(STABLE_LENGTH + 0x100, 4));
    }

    #[test]
    fn a_hive_layer_reports_end_of_data_above_its_top_and_a_hole_inside_it() {
        let profile = xp_profile();
        let hive = HiveSpace::open(&profile, XP_CMHIVE).unwrap();
        let layer: Arc<dyn MemoryLayer> = Arc::<HiveSpace>::clone(&hive);

        let mut buf = [0u8; 8];
        assert_eq!(
            layer.read_at(layer.max_address() + 1, &mut buf).unwrap(),
            0,
            "above the top of the space is end of data, not a hole"
        );

        let err = layer
            .read_at(STABLE_LENGTH + 0x100, &mut buf)
            .expect_err("inside the span with nothing behind it is a hole");
        assert!(MemoryHole::from_io(&err).is_some());

        match layer.mapping(layer.max_address() + 1, 4) {
            Err(LayerError::OutOfRange { .. }) => {}
            other => panic!("expected OutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn a_win8_shaped_hmap_entry_is_read_as_a_bin_address_plus_a_block_offset() {
        // Windows 8 split the entry into a bin address with flag bits in the
        // bottom nibble and the block's offset inside the bin. Reading it the
        // pre-Windows-8 way would land on the start of the bin: a real cell, at
        // the wrong place.
        let profile = win8_profile();
        let hive = HiveSpace::open(&profile, WIN8_CMHIVE).unwrap();
        let located = hive.translate(CellIndex::new(WIN8_ROOT_CELL)).unwrap();
        assert_eq!(
            located.address,
            WIN8_BIN_VA + 0x1000 + u64::from(WIN8_ROOT_CELL)
        );
    }

    #[test]
    fn a_sixty_four_bit_hive_is_read_at_the_pointer_width_the_symbol_table_declares() {
        let profile = win8_profile();
        let hive = HiveSpace::open(&profile, WIN8_CMHIVE).unwrap();
        assert_eq!(hive.store_length(Store::Stable), 0x2000);
        let root = hive.root_cell().expect("a resident base block");
        assert_eq!(root.value.raw(), WIN8_ROOT_CELL);
    }

    #[test]
    fn the_cell_header_length_is_cross_checked_against_the_symbol_table_when_it_can_be() {
        // A table that has no `_HCELL` uses the format's constant.
        let profile = xp_profile();
        assert_eq!(cell_header_len(&profile.symbols).unwrap(), CELL_HEADER_LEN);
        // A table that does have one must agree with it.
        let (agreeing, disagreeing) = hcell_tables();
        assert_eq!(cell_header_len(&agreeing).unwrap(), CELL_HEADER_LEN);
        let err = cell_header_len(&disagreeing)
            .expect_err("a table that moves the cell contents must be refused");
        assert_eq!(err.class(), "malformed");
    }

    /// The cross-check is available or it is not, and "not" is not a stage
    /// failure: this is the `_OBJECT_HEADER.InfoMask` shape, where a member no
    /// reading path needs was proved fatally and killed the stage.
    #[test]
    fn an_hcell_without_the_member_the_cross_check_reads_still_yields_the_formats_length() {
        let symbols = hcell_table_without_contents();
        assert!(
            symbols.has_type("_HCELL"),
            "the fixture must declare the type, or it tests the other branch"
        );
        assert!(!symbols.has_member("_HCELL", "u"));
        assert_eq!(
            cell_header_len(&symbols).expect(
                "a member that cannot be cross-checked against is not a reason to refuse the \
                 registry"
            ),
            CELL_HEADER_LEN
        );
    }

    #[test]
    fn an_array_members_element_width_comes_from_the_symbol_table() {
        let profile = xp_profile();
        let (width, count) = array_shape(&profile.symbols, "_CM_KEY_INDEX", "List").unwrap();
        assert_eq!(
            width, 4,
            "cell indices are four bytes on every architecture"
        );
        assert_eq!(count, 1, "the format declares one and stores Count of them");

        let err = array_shape(&profile.symbols, "_CM_KEY_INDEX", "Count")
            .expect_err("an integer member is not an array");
        assert!(err.to_string().contains("array"), "{err}");
    }
}
