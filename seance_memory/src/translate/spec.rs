//! [`PagingSpec`]: the parameter table that turns "which paging mode was this
//! machine in?" into the arithmetic of a page-table walk.
//!
//! Four numbers and one level list drive every Intel paging mode, and getting
//! any of them wrong produces a *plausible* physical address rather than an
//! obvious failure. That is why they live in one table instead of being spread
//! through the walker:
//!
//! | Mode | entry | register | MAXPHYADDR | MAXVIRTADDR | levels (index bits, leaf rule) |
//! |---|---|---|---|---|---|
//! | [`PagingMode::Intel32`] | 4 B | 32 | 32 | 32 | PD(10, PS), PT(10, page) |
//! | [`PagingMode::IntelPae`] | 8 B | 32 | 40 | 32 | PDPT(2, table only), PD(9, PS), PT(9, page) |
//! | [`PagingMode::Intel32e`] | 8 B | 64 | 52 | 48 | PML4(9, table only), PDPT(9, PS), PD(9, PS), PT(9, page) |
//! | [`PagingMode::Intel32eLa57`] | 8 B | 64 | 52 | 57 | PML5(9, table only), PML4(9, table only), PDPT(9, PS), PD(9, PS), PT(9, page) |
//! | [`PagingMode::Arm64`] 4 KiB, 48-bit | 8 B | 64 | 48 | 48 per regime | L0(9, table only), L1(9, block), L2(9, block), L3(9, page) |
//! | [`PagingMode::Arm64`] 16 KiB, 48-bit | 8 B | 64 | 48 | 48 per regime | L0(1, table only), L1(11, table only), L2(11, block), L3(11, page) |
//! | [`PagingMode::Arm64`] 64 KiB, 48-bit | 8 B | 64 | 48 | 48 per regime | L1(6, table only), L2(13, block), L3(13, page) |
//!
//! The ARM64 rows are for a 48-bit regime; a smaller `T0SZ`/`T1SZ` drops top
//! levels and narrows the first one, which [`PagingSpec::new`] derives from
//! the regime's own numbers rather than from a second table (see
//! [`Arm64Regime`]). How an entry ends the walk is no longer one line in the
//! walker: each level carries a [`LeafRule`] and [`PagingSpec::classify`]
//! applies it, so the Intel assumption — bit 7 on a present entry, bit 12 as
//! the high PAT index — is one rule among several rather than the walker's
//! shape.
//!
//! # MAXPHYADDR is a per-(mode, OS) cell, not a property of the OS
//!
//! Windows narrows MAXPHYADDR to **45** bits, but *only* on x86-64: the bits
//! above 45 in an x64 entry carry Windows' own software state, and folding them
//! into the physical address silently corrupts every transition PTE. It does
//! **not** narrow 32-bit or PAE entries, whose architectural widths are 32 and
//! 40. Applying an OS override across all modes widens the frame mask past the
//! architectural width and yields wrong physical addresses on any entry with
//! bits set above the real one. So the override is carried per cell — see
//! [`PagingSpec::new`] — and never as a property of [`PteSemantics`] alone.
//!
//! # What an examiner gets from this
//!
//! Two images, same bytes, different declared mode, produce different physical
//! addresses for the same virtual address. Nothing downstream can detect that,
//! so the mode is a *declared* input recorded in layer metadata, never guessed
//! here.

/// Which hardware paging structure the machine was using when it was captured.
///
/// This is a structural fact about the guest, established by the image profiler
/// (a crash dump's header, a VMCOREINFO note, a validated DTB self-reference
/// test), never inferred by this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PagingMode {
    /// 32-bit paging without PAE: two levels of 4-byte entries, 4 KiB and
    /// 4 MiB pages. 32-bit Windows before PAE became the default, and any
    /// 32-bit Linux built without `CONFIG_X86_PAE`.
    Intel32,
    /// PAE paging: a 4-entry page-directory-pointer table above two levels of
    /// 8-byte entries, 4 KiB and 2 MiB pages. This is the mode that carries the
    /// NX bit onto 32-bit systems, and the one whose top table is 32 bytes
    /// rather than a page — the detail that breaks walkers which hardcode
    /// 4 KiB table alignment.
    IntelPae,
    /// IA-32e (x86-64) paging: four levels of 8-byte entries, 4 KiB, 2 MiB and
    /// 1 GiB pages, with 48-bit sign-extended virtual addresses.
    Intel32e,
    /// IA-32e with LA57: the same 8-byte entries and the same page sizes, with
    /// a fifth table (the PML5) above the PML4 and 57-bit sign-extended virtual
    /// addresses.
    ///
    /// # Why the depth is a declared fact and never a fallback
    ///
    /// Whether a machine was running in this mode is `CR4.LA57`, which is
    /// register state: no raw dump, LiME capture or ELF core publishes it. So
    /// this mode is declared by the image profiler on evidence, exactly like
    /// [`PagingMode::Intel32e`], and an image whose depth could not be
    /// established is refused rather than walked at a guessed depth.
    ///
    /// Getting the depth wrong is not a near miss. A five-level hierarchy
    /// walked four levels deep mistakes the PML5 for a PML4 and indexes every
    /// table below it with the wrong nine bits of the address, so every
    /// translation lands somewhere and none of them lands right. Walking a
    /// four-level hierarchy five levels deep does the same in reverse.
    ///
    /// The Linux tier establishes it by proof rather than by assertion: the
    /// kernel's page tables are walked at each candidate depth and the banner's
    /// virtual address must come back to the physical address the sweep found
    /// it at, with the same bytes. A depth that does not do that is not used.
    Intel32eLa57,
    /// VMSAv8-64 — AArch64 stage-1 translation under one translation regime
    /// (ARM DDI 0487, chapter D8).
    ///
    /// An ARM64 address space is not one hierarchy but two: `TTBR0_EL1`
    /// roots the bottom of the 64-bit space and `TTBR1_EL1` the top, each
    /// sized by its own `TCR_EL1.T0SZ` / `T1SZ`, and the hardware chooses the
    /// root by the address's upper bits. This crate models each regime as its
    /// own [`PagingSpec`] — and therefore its own
    /// [`VirtualLayer`](crate::translate::VirtualLayer) — rooted at that
    /// regime's TTBR. A kernel address space is the TTBR1 layer; a process is
    /// the TTBR0 layer built from its own `TTBR0` value.
    ///
    /// The granule, the regime and the VA width are all `TCR_EL1` fields:
    /// register state that no raw dump publishes. Exactly as with
    /// `CR4.LA57`, they are declared by the profiler on evidence (a
    /// recorded `TCR_EL1` through [`Arm64Regime::from_tcr_el1`], a
    /// `VMCOREINFO` note, a walk that translates the kernel banner back to
    /// where it was found) and never guessed here.
    Arm64(Arm64Regime),
}

impl PagingMode {
    /// Stable identifier for artifact metadata and log lines.
    ///
    /// For ARM64 this names the granule and the regime; the VA width, which
    /// is not one of a fixed set, is published beside it as its own note.
    pub fn as_str(self) -> &'static str {
        match self {
            PagingMode::Intel32 => "intel32",
            PagingMode::IntelPae => "intel_pae",
            PagingMode::Intel32e => "intel32e",
            PagingMode::Intel32eLa57 => "intel32e_la57",
            PagingMode::Arm64(regime) => regime.as_str(),
        }
    }

    /// Whether this is one of the Intel modes.
    ///
    /// The one question a Windows convention may ask before applying itself:
    /// every Windows software-PTE layout this crate decodes was read out of
    /// x86 and x64 entries, and applying it to an ARM64 descriptor would
    /// decode hardware attribute bits as a pagefile number.
    pub fn is_intel(self) -> bool {
        !matches!(self, PagingMode::Arm64(_))
    }

    /// The ARM64 regime, when this is an ARM64 mode.
    pub fn arm64(self) -> Option<Arm64Regime> {
        match self {
            PagingMode::Arm64(regime) => Some(regime),
            _ => None,
        }
    }
}

impl std::fmt::Display for PagingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PagingMode::Arm64(regime) => {
                write!(f, "{} ({}-bit VA)", regime.as_str(), regime.va_bits())
            }
            other => f.write_str(other.as_str()),
        }
    }
}

/// The translation granule: the page size, and therefore the size of every
/// table below the top one (`TCR_EL1.TG0` / `TG1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arm64Granule {
    /// 4 KiB pages, 512-entry tables, blocks of 2 MiB (level 2) and 1 GiB
    /// (level 1); FEAT_LPA2 adds a 512 GiB level-0 block this build does not
    /// decode. What every mainstream Linux and Android arm64 kernel ships.
    Kb4,
    /// 16 KiB pages, 2048-entry tables, 32 MiB blocks at level 2; FEAT_LPA2
    /// adds a 64 GiB level-1 block this build does not decode. The granule
    /// Apple silicon and some Android kernels use.
    Kb16,
    /// 64 KiB pages, 8192-entry tables, 512 MiB blocks at level 2; FEAT_LPA
    /// adds a 4 TiB level-1 block this build does not decode.
    Kb64,
}

impl Arm64Granule {
    /// `log2` of the page size: 12, 14 or 16.
    pub const fn page_shift(self) -> u32 {
        match self {
            Arm64Granule::Kb4 => 12,
            Arm64Granule::Kb16 => 14,
            Arm64Granule::Kb64 => 16,
        }
    }

    /// Address bits one full table of this granule indexes: the page shift
    /// less the three bits of an eight-byte entry.
    pub const fn index_bits(self) -> u32 {
        self.page_shift() - 3
    }

    /// Whether this build decodes a block descriptor at ARM level `level`:
    /// the levels D8.3.1 ("Block descriptor") permits one at **without**
    /// FEAT_LPA or FEAT_LPA2 — 4 KiB at levels 1 and 2, 16 KiB and 64 KiB at
    /// level 2.
    ///
    /// The architecture permits more. FEAT_LPA adds a 64 KiB level-1 block
    /// (4 TiB) and FEAT_LPA2 a 4 KiB level-0 (512 GiB) and a 16 KiB level-1
    /// (64 GiB) block; both also move output-address bits into positions
    /// this crate reads as attributes, and whether either is in force —
    /// `TCR_EL1.DS` for LPA2, the PE's `ID_AA64MMFR0_EL1.PARange` for LPA —
    /// is register state no image records. Those blocks are therefore
    /// *refused by this implementation*, not denied by the architecture: see
    /// [`Arm64Granule::block_permitted_only_under_lpa`] for how a `0b01`
    /// descriptor at such a level is reported.
    const fn block_permitted_at(self, level: u32) -> bool {
        match self {
            Arm64Granule::Kb4 => level == 1 || level == 2,
            Arm64Granule::Kb16 | Arm64Granule::Kb64 => level == 2,
        }
    }

    /// Whether ARM level `level` carries a block descriptor only under
    /// FEAT_LPA (64 KiB level 1) or FEAT_LPA2 (4 KiB level 0, 16 KiB level
    /// 1).
    ///
    /// At such a level a valid descriptor with the type bit clear is a block
    /// on hardware with the feature on and a reserved, faulting encoding
    /// without it, and when its extra output-address bits are clear nothing
    /// in the entry says which. The classifier reports it as
    /// [`EntryKind::Unnameable`]: neither a frame this build cannot vouch
    /// for nor an absence it cannot vouch for. Every other level where
    /// [`block_permitted_at`](Self::block_permitted_at) is false — a 16 KiB
    /// level 0 — is reserved under every feature the architecture defines,
    /// and a `0b01` descriptor there is invalid.
    const fn block_permitted_only_under_lpa(self, level: u32) -> bool {
        match self {
            Arm64Granule::Kb4 => level == 0,
            Arm64Granule::Kb16 | Arm64Granule::Kb64 => level == 1,
        }
    }

    /// Why a `0b01` descriptor at the level
    /// [`block_permitted_only_under_lpa`](Self::block_permitted_only_under_lpa)
    /// names cannot be decoded, for the refusal's own words.
    const fn undecoded_lpa_block_detail(self) -> &'static str {
        match self {
            Arm64Granule::Kb4 => {
                "a valid descriptor with the type bit clear at level 0 of a 4 KiB granule is a \
                 512 GiB block under FEAT_LPA2 and a reserved, faulting encoding without it; \
                 which is in force is TCR_EL1.DS, which no image records, so this build states \
                 neither the frame nor absence"
            }
            Arm64Granule::Kb16 => {
                "a valid descriptor with the type bit clear at level 1 of a 16 KiB granule is a \
                 64 GiB block under FEAT_LPA2 and a reserved, faulting encoding without it; \
                 which is in force is TCR_EL1.DS, which no image records, so this build states \
                 neither the frame nor absence"
            }
            Arm64Granule::Kb64 => {
                "a valid descriptor with the type bit clear at level 1 of a 64 KiB granule is a \
                 4 TiB block on a PE that implements FEAT_LPA and a reserved, faulting encoding \
                 on one that does not; which this was is ID_AA64MMFR0_EL1.PARange, which no \
                 image records, so this build states neither the frame nor absence"
            }
        }
    }

    /// Stable identifier fragment.
    pub const fn as_str(self) -> &'static str {
        match self {
            Arm64Granule::Kb4 => "4k",
            Arm64Granule::Kb16 => "16k",
            Arm64Granule::Kb64 => "64k",
        }
    }
}

impl std::fmt::Display for Arm64Granule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which of the two translation table base registers roots a regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ttbr {
    /// `TTBR0_EL1`: the bottom of the address space, where the upper
    /// `64 - T0SZ` bits of every address are zero. User space under Linux.
    Ttbr0,
    /// `TTBR1_EL1`: the top of the address space, where the upper
    /// `64 - T1SZ` bits of every address are one. The kernel under Linux.
    Ttbr1,
}

/// One ARM64 translation regime: a granule, a root register and a VA width.
///
/// Built through [`Arm64Regime::new`] or [`Arm64Regime::from_tcr_el1`],
/// both of which refuse a width the architecture does not define, so a
/// [`PagingSpec`] can be derived from one without a failure path of its own.
/// A regime built from a recorded `TCR_EL1` also carries the fields of it
/// that change what a walk may claim: `IPS`, `TBIn`, `HPDn` and `EPDn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Arm64Regime {
    granule: Arm64Granule,
    ttbr: Ttbr,
    va_bits: u8,
    /// The output-address width `TCR_EL1.IPS` allows, clamped to
    /// [`ARM64_MAX_OA_BITS`]. 48 for a regime built by [`Arm64Regime::new`],
    /// which is the widest a descriptor without FEAT_LPA can name, so a
    /// regime whose IPS was never recorded enforces nothing it cannot know.
    ips_bits: u8,
    /// `TCR_EL1.TBI0` / `TBI1` for this regime: the hardware ignores bits
    /// 63:56 of an address. Off unless a recorded `TCR_EL1` says it was on.
    tbi: bool,
    /// `TCR_EL1.HPD0` / `HPD1` for this regime: the hierarchical permission
    /// bits of table descriptors are ignored. Off unless a recorded
    /// `TCR_EL1` says it was on; without FEAT_HPDS the field is RES0 and the
    /// hierarchical bits always apply.
    hpd: bool,
    /// `TCR_EL1.EPD0` / `EPD1` for this regime: the hardware makes no walk
    /// through this TTBR at the moment the register was recorded.
    walks_disabled: bool,
    /// `TCR_EL1.DS = 1` under a 16 KiB granule: the FEAT_LPA2 descriptor layout,
    /// in which output-address bits 51:50 sit in descriptor bits 9:8 (where
    /// shareability lived), bits 49:48 are address bits, a level-1 block is
    /// 64 GiB and the width may be 52 bits. Only a regime built from a
    /// recorded `TCR_EL1` can be one.
    lpa2: bool,
}

/// Address bits 63:56, which top-byte-ignore sets aside (D8.8).
const ARM64_TAG_MASK: u64 = 0xFF00_0000_0000_0000;

/// The widest output address a VMSAv8-64 descriptor names without FEAT_LPA
/// or FEAT_LPA2 (both refused): bits 47:0.
pub const ARM64_MAX_OA_BITS: u8 = 48;

/// Smallest VA width VMSAv8-64 defines: `TxSZ = 39`, 25 bits.
pub const ARM64_MIN_VA_BITS: u8 = 25;

/// Largest VA width without FEAT_LPA2: `TxSZ = 16`, 48 bits. A 52-bit width
/// needs FEAT_LPA2 (4 KiB and 16 KiB) or FEAT_LVA (64 KiB), both of which
/// move output-address bits into positions this crate reads as attributes.
pub const ARM64_MAX_VA_BITS: u8 = 48;

/// Largest VA width under FEAT_LPA2 and a 16 KiB granule: `TxSZ = 12`, 52
/// bits, with a 32-entry level 0 above three full levels.
pub const ARM64_MAX_VA_BITS_LPA2: u8 = 52;

/// The widest output address a descriptor names under FEAT_LPA2: bits 51:0.
pub const ARM64_MAX_OA_BITS_LPA2: u8 = 52;

impl Arm64Regime {
    /// A regime of `va_bits` bits (`64 - TxSZ`) under `granule`, rooted at
    /// `ttbr`.
    ///
    /// `va_bits` must lie in `25..=48`: `TxSZ` is architecturally 16..=39
    /// without FEAT_LPA2, and a 52-bit regime would need the LPA2 descriptor
    /// layout, which is refused rather than approximated — see
    /// [`ARM64_MAX_VA_BITS`].
    pub const fn new(granule: Arm64Granule, ttbr: Ttbr, va_bits: u8) -> Result<Self, &'static str> {
        if va_bits < ARM64_MIN_VA_BITS {
            return Err("an ARM64 regime is at least 25 bits wide (TxSZ at most 39)");
        }
        if va_bits > ARM64_MAX_VA_BITS {
            return Err(
                "an ARM64 regime wider than 48 bits needs FEAT_LPA2 or FEAT_LVA, whose \
                 descriptor layout this build does not decode",
            );
        }
        Ok(Self {
            granule,
            ttbr,
            va_bits,
            ips_bits: ARM64_MAX_OA_BITS,
            tbi: false,
            hpd: false,
            walks_disabled: false,
            lpa2: false,
        })
    }

    /// The regime a recorded `TCR_EL1` value selects for `ttbr`.
    ///
    /// Decodes the fields ARM DDI 0487 (D17, `TCR_EL1`) gives each regime:
    ///
    /// | field | TTBR0 | TTBR1 |
    /// |---|---|---|
    /// | `TxSZ` (VA width `64 - TxSZ`) | `T0SZ` 5:0 | `T1SZ` 21:16 |
    /// | walk disabled | `EPD0` 7 | `EPD1` 23 |
    /// | granule | `TG0` 15:14: `00` 4K, `01` 64K, `10` 16K | `TG1` 31:30: `01` 16K, `10` 4K, `11` 64K |
    /// | top-byte-ignore | `TBI0` 37 | `TBI1` 38 |
    /// | hierarchical permissions disabled | `HPD0` 41 | `HPD1` 42 |
    ///
    /// and the shared `IPS` (34:32: 32, 36, 40, 42, 44, 48, 52 bits) and `DS`
    /// (59). The two `TG` fields encode the granules differently, so reading
    /// one with the other's table swaps 4 KiB and 16 KiB.
    ///
    /// # Refused, by name
    ///
    /// * `DS = 1` under a 4 or 64 KiB granule. FEAT_LPA2 is decoded for the
    ///   16 KiB granule only, because that is the one layout graded against a
    ///   real capture (`MEM-043`); a 4 KiB LPA2 regime adds a level above the
    ///   ones this build walks, and `DS` under a 64 KiB granule is FEAT_LPA's
    ///   business, not LPA2's.
    /// * A reserved `TG0` / `TG1` encoding for the regime asked about (the
    ///   other regime's field is not consulted).
    /// * `TxSZ` outside `16..=39` (see [`Arm64Regime::new`]).
    /// * `IPS = 0b111`, which this build does not decode.
    ///
    /// `IPS = 0b110` (52 bits) is recorded as 52 under `DS = 1` and as 48
    /// otherwise: without `DS` a 4 or 16 KiB descriptor names 48 bits at most,
    /// and a 64 KiB FEAT_LPA descriptor is refused where it is read.
    ///
    /// `EPDn = 1` is recorded, not refused: the register is one moment of the
    /// machine, and the tables it would have walked may still be the
    /// evidence. [`Arm64Regime::walks_disabled`] says so.
    pub const fn from_tcr_el1(tcr: u64, ttbr: Ttbr) -> Result<Self, &'static str> {
        let ds = (tcr >> 59) & 1 == 1;
        let (txsz, epd, granule, tbi, hpd) = match ttbr {
            Ttbr::Ttbr0 => (
                tcr & 0x3f,
                (tcr >> 7) & 1 == 1,
                match (tcr >> 14) & 0b11 {
                    0b00 => Arm64Granule::Kb4,
                    0b01 => Arm64Granule::Kb64,
                    0b10 => Arm64Granule::Kb16,
                    _ => return Err("TCR_EL1.TG0 holds the reserved encoding 0b11"),
                },
                (tcr >> 37) & 1 == 1,
                (tcr >> 41) & 1 == 1,
            ),
            Ttbr::Ttbr1 => (
                (tcr >> 16) & 0x3f,
                (tcr >> 23) & 1 == 1,
                match (tcr >> 30) & 0b11 {
                    0b01 => Arm64Granule::Kb16,
                    0b10 => Arm64Granule::Kb4,
                    0b11 => Arm64Granule::Kb64,
                    _ => return Err("TCR_EL1.TG1 holds the reserved encoding 0b00"),
                },
                (tcr >> 38) & 1 == 1,
                (tcr >> 42) & 1 == 1,
            ),
        };
        if ds && !matches!(granule, Arm64Granule::Kb16) {
            return Err(
                "TCR_EL1.DS is set under a 4 or 64 KiB granule: the FEAT_LPA2 descriptor \
                 layout is decoded for the 16 KiB granule only",
            );
        }
        let ips_bits = match (tcr >> 32) & 0b111 {
            0b000 => 32,
            0b001 => 36,
            0b010 => 40,
            0b011 => 42,
            0b100 => 44,
            0b101 => ARM64_MAX_OA_BITS,
            0b110 if ds => ARM64_MAX_OA_BITS_LPA2,
            0b110 => ARM64_MAX_OA_BITS,
            _ => return Err("TCR_EL1.IPS holds 0b111, which this build does not decode"),
        };
        // `txsz` is six bits, so `64 - txsz` cannot underflow; the width must
        // lie in 25..=48, or 25..=52 under LPA2 (a `TxSZ` of 12 to 39).
        let va_bits = (64 - txsz) as u8;
        let mut regime = if ds && va_bits > ARM64_MAX_VA_BITS && va_bits <= ARM64_MAX_VA_BITS_LPA2 {
            // A 52-bit width: `new` would refuse it, and only LPA2 permits it.
            let mut wide = match Self::new(granule, ttbr, ARM64_MAX_VA_BITS) {
                Ok(regime) => regime,
                Err(err) => return Err(err),
            };
            wide.va_bits = va_bits;
            wide
        } else {
            match Self::new(granule, ttbr, va_bits) {
                Ok(regime) => regime,
                Err(err) => return Err(err),
            }
        };
        regime.lpa2 = ds;
        regime.ips_bits = ips_bits;
        regime.tbi = tbi;
        regime.hpd = hpd;
        regime.walks_disabled = epd;
        Ok(regime)
    }

    /// The output-address width this regime permits (`TCR_EL1.IPS`, at most
    /// 48 bits, or 52 under LPA2).
    pub const fn ips_bits(self) -> u8 {
        self.ips_bits
    }

    /// Whether this regime uses the FEAT_LPA2 descriptor layout (`TCR_EL1.DS =
    /// 1`, 16 KiB granule).
    pub const fn lpa2(self) -> bool {
        self.lpa2
    }

    /// This regime with top-byte-ignore (`TCR_EL1.TBI0` / `TBI1`) set as
    /// `on`, for a caller that knows the register's value from the operating
    /// system's own fixed configuration rather than from a recorded
    /// `TCR_EL1`. Linux arm64 sets `TBI0` unconditionally for user space
    /// (`arch/arm64/mm/proc.S`, `__cpu_setup`).
    pub const fn with_top_byte_ignore(mut self, on: bool) -> Self {
        self.tbi = on;
        self
    }

    /// Whether top-byte-ignore is on for this regime.
    pub const fn tbi(self) -> bool {
        self.tbi
    }

    /// Whether hierarchical permissions are disabled for this regime.
    pub const fn hierarchical_permissions_disabled(self) -> bool {
        self.hpd
    }

    /// Whether the recorded `TCR_EL1` disabled walks through this TTBR.
    pub const fn walks_disabled(self) -> bool {
        self.walks_disabled
    }

    /// The granule.
    pub const fn granule(self) -> Arm64Granule {
        self.granule
    }

    /// Which register roots this regime.
    pub const fn ttbr(self) -> Ttbr {
        self.ttbr
    }

    /// The VA width, `64 - TxSZ`.
    pub const fn va_bits(self) -> u8 {
        self.va_bits
    }

    /// Stable identifier: granule and regime.
    pub const fn as_str(self) -> &'static str {
        match (self.granule, self.ttbr) {
            (Arm64Granule::Kb4, Ttbr::Ttbr0) => "arm64_4k_ttbr0",
            (Arm64Granule::Kb4, Ttbr::Ttbr1) => "arm64_4k_ttbr1",
            (Arm64Granule::Kb16, Ttbr::Ttbr0) => "arm64_16k_ttbr0",
            (Arm64Granule::Kb16, Ttbr::Ttbr1) => "arm64_16k_ttbr1",
            (Arm64Granule::Kb64, Ttbr::Ttbr0) => "arm64_64k_ttbr0",
            (Arm64Granule::Kb64, Ttbr::Ttbr1) => "arm64_64k_ttbr1",
        }
    }
}

/// Whose software conventions govern an entry the hardware would reject.
///
/// The paging *structure* is the CPU's; the meaning of a **non-present** entry
/// belongs entirely to the operating system, which is free to store anything it
/// likes in the other 63 bits. Reading those bits under the wrong convention is
/// how a tool reports a pagefile offset as a physical address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PteSemantics {
    /// Present bit only. Any entry with bit 0 clear is simply not resident, and
    /// nothing further is claimed about it.
    ///
    /// This is the correct choice for an image whose OS is not yet established,
    /// and for any OS this module has no conventions for. A Linux image should
    /// use [`PteSemantics::Linux`], which says strictly more without claiming
    /// anything `Bare` would not.
    Bare,
    /// Linux's conventions for a non-present entry, as far as they can be read
    /// **without knowing which kernel source built the image**.
    ///
    /// # What this adds over [`PteSemantics::Bare`]
    ///
    /// Three of Linux's own predicates are compile-time constants across every
    /// x86-64 kernel, so they can be applied to an entry with no version fact
    /// at all:
    ///
    /// - `pte_none()` — an entry that is zero once the accessed and dirty bits
    ///   are masked off (`_PAGE_KNL_ERRATUM_MASK`; some processors set those
    ///   two on a non-present entry, and Linux ignores them for exactly that
    ///   reason). Nothing was ever mapped here.
    /// - `pte_present()` — Linux counts `_PAGE_PROTNONE`, which it aliases onto
    ///   bit 8, as present. An entry with bit 8 set and bit 0 clear is a
    ///   `PROT_NONE` or NUMA-balancing mapping: the kernel holds a frame for it
    ///   and the hardware still faults. It is **not** a swapped page.
    /// - anything else non-present — a `swp_entry_t`. The kernel moved this
    ///   page's contents out of the frame and wrote down where, which is a
    ///   different finding from "this address was never mapped".
    ///
    /// That third case becomes [`InvalidEntry::LinuxSwapEntry`], and it is the
    /// whole gain: under `Bare` a swapped page and a page that never existed
    /// are the same answer.
    ///
    /// # Why the swap location itself is refused
    ///
    /// The bit positions of the swap *type* (which area) and *offset* (which
    /// page in it) are a property of the kernel **source**, and they have moved
    /// at least three times on x86-64 alone: type at bits 5:1 with the offset
    /// above bit 9 up to Linux 3.x; type at bits 13:9 with the offset above bit
    /// 14 through 4.x; and since the L1TF mitigation the type at bits 63:59
    /// with the offset stored **inverted** below it.
    ///
    /// The obvious selector — the release string in the kernel banner — does
    /// not work, and this is the reason no decode is attempted rather than a
    /// reason to be careful. The L1TF change was backported into the 4.4, 4.9,
    /// 4.14 and 4.17 stable series and into distribution kernels below 4.19
    /// (Ubuntu shipped it on 4.15), so a kernel that calls itself 4.15 may use
    /// either layout and its version string cannot say which. Nothing else in a
    /// memory image states it either: it is not a runtime variable, so there is
    /// no symbol to read and no VMCOREINFO field that names it.
    ///
    /// A decode against the wrong layout does not fail. It yields a small,
    /// plausible area number and a plausible page offset, and reading that
    /// offset out of a swap area the examiner supplied returns *some* page's
    /// contents, attributed to this virtual address. So the swap-family entry
    /// is reported as one and no number is put on it.
    Linux,
    /// Windows' memory-manager conventions on top of the hardware bits.
    ///
    /// Two of them change what an examiner can recover:
    ///
    /// - A **transition** PTE (bit 11 set, bit 10 clear) describes a page that
    ///   is still in RAM on the standby or modified list. The hardware calls it
    ///   absent; the page frame number is intact and the page is readable. This
    ///   is where freed-but-not-yet-reused evidence lives, so treating such an
    ///   entry as present is a recovery capability, not a liberty.
    /// - A **software** PTE (valid, transition and prototype all clear) encodes
    ///   the pagefile number and the page's offset within it. Those bytes are on
    ///   the suspect's disk, not in this image, and saying so is a different
    ///   fact from "the page is gone".
    Windows,
}

impl PteSemantics {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            PteSemantics::Bare => "bare",
            PteSemantics::Linux => "linux",
            PteSemantics::Windows => "windows",
        }
    }
}

impl std::fmt::Display for PteSemantics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bit 0 of every Intel paging entry: the table or page is resident in RAM and
/// the hardware will use the rest of the entry as an address.
pub const PRESENT_BIT: u64 = 1;

/// Bit 7. On a level that supports it, PS=1 ends the walk in a large page. On a
/// final-level PTE the same bit is the PAT index and must **not** be read as a
/// large-page flag.
pub const LARGE_PAGE_BIT: u64 = 1 << 7;

/// Bit 12 of a **large-page** entry: the high PAT index bit. It sits inside the
/// range the 4 KiB frame mask would use, so it is cleared before a large frame
/// is extracted.
pub const PAT_LARGE_BIT: u64 = 1 << 12;

/// Bit 10 of a non-present Windows entry: this is a prototype PTE, describing
/// shared or file-backed memory whose real state lives in a section object.
pub const WINDOWS_PROTOTYPE_BIT: u64 = 1 << 10;

/// Bit 11 of a non-present Windows entry: the page is in transition — still
/// resident in RAM, on the standby or modified list, with a usable frame.
pub const WINDOWS_TRANSITION_BIT: u64 = 1 << 11;

/// Bits 4:1 of a Windows software PTE: which pagefile holds the page.
pub const WINDOWS_PAGEFILE_INDEX_MASK: u64 = 0xF;

/// Bit 8 of a Linux entry: `_PAGE_PROTNONE`, which Linux aliases onto
/// `_PAGE_GLOBAL` because a non-present entry has no use for the global bit.
///
/// `pte_present()` on x86 is `_PAGE_PRESENT | _PAGE_PROTNONE`, so an entry with
/// this bit set and bit 0 clear is a page the **kernel** considers mapped and
/// the hardware refuses to translate: a `PROT_NONE` region, or a NUMA-balancing
/// hint. Its frame is not readable here — since the L1TF mitigation the frame
/// number in a non-present entry is stored inverted, which is the same unknown
/// that stops a swap decode — but the one thing that must not happen is for it
/// to be counted as a swapped page, because nothing was written to any swap
/// area.
pub const LINUX_PROTNONE_BIT: u64 = 1 << 8;

/// Bits 5 and 6 — accessed and dirty — which Linux masks out of its own
/// "is this entry empty?" test on x86-64 (`_PAGE_KNL_ERRATUM_MASK`).
///
/// Some processors set those two bits on an entry the hardware would reject,
/// and `pte_none()` ignores them for that reason. Honouring the same mask keeps
/// a spuriously-flagged empty entry out of the swap-family bucket, which would
/// otherwise report a page that was never mapped as one whose contents the
/// kernel moved somewhere.
pub const LINUX_EMPTY_ENTRY_IGNORED_BITS: u64 = (1 << 5) | (1 << 6);

/// Bit position of `MMPTE_PROTOTYPE.ProtoAddress` in an x64 entry.
///
/// The field is `LONGLONG ProtoAddress : 48` at bits 63:16 and holds the whole
/// kernel virtual address of the prototype `_MMPTE`, sign-extended — so an
/// *arithmetic* shift recovers it and a logical one silently loses the upper
/// canonical half, which is where every prototype array lives.
pub const WINDOWS_X64_PROTO_ADDRESS_SHIFT: u32 = 16;

/// Bit position of `MMPTE_PROTOTYPE.ProtoAddress` in a PAE entry: bits 63:32,
/// an unsigned 32-bit kernel virtual address.
pub const WINDOWS_PAE_PROTO_ADDRESS_SHIFT: u32 = 32;

/// Bit 63: the no-execute bit, when the machine enabled it.
///
/// Its only relevance to translation is negative — it must never be mistaken
/// for a physical address bit. Every frame mask here stops at MAXPHYADDR, which
/// is at most 52, so it cannot be.
pub const NX_BIT: u64 = 1 << 63;

/// Bit 1 of an ARM64 descriptor (D8.3.1): on a valid entry above the last
/// level, set means a table descriptor and clear a block descriptor; at the
/// last level, set means a page descriptor and clear is reserved.
pub const ARM64_TABLE_BIT: u64 = 1 << 1;

/// Bit 53 of an ARM64 block or page descriptor: privileged execute-never.
pub const ARM64_PXN_BIT: u64 = 1 << 53;

/// Bit 54 of an ARM64 block or page descriptor: unprivileged execute-never
/// (`XN` in a regime with a single exception level).
pub const ARM64_UXN_BIT: u64 = 1 << 54;

/// Bit 59 of an ARM64 table descriptor: `PXNTable`, privileged
/// execute-never for everything below it (D8.4.2).
pub const ARM64_PXN_TABLE_BIT: u64 = 1 << 59;

/// Bit 60 of an ARM64 table descriptor: `UXNTable` (`XNTable` in a regime
/// with a single exception level), unprivileged execute-never for everything
/// below it.
pub const ARM64_UXN_TABLE_BIT: u64 = 1 << 60;

/// Bits 49:48 of a 4 KiB or 16 KiB granule descriptor: RES0 for a 48-bit
/// output address and output-address bits 49:48 under FEAT_LPA2. Non-zero
/// means a frame this crate's 48-bit reading cannot state, and the entry is
/// refused rather than masked.
pub const ARM64_LPA2_OA_BITS: u64 = 0b11 << 48;

/// Bits 15:12 of a 64 KiB granule descriptor: RES0 for a 48-bit output
/// address and output-address bits 51:48 under FEAT_LPA. Same treatment.
pub const ARM64_LPA_OA_BITS: u64 = 0xF << 12;

/// How a level decides whether a present entry ends the walk.
///
/// This is the thing that used to be one line in the walker — `large_page
/// && present && bit 7`, then a frame mask with bit 12 cleared — and it is
/// the line that carried the Intel assumption. Each rule states which bits
/// it reads and what they mean, so an architecture that encodes "page or
/// table" differently is a new rule rather than a new walker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafRule {
    /// Every present entry names a table. A top-level Intel entry (Intel
    /// defines no 512 GiB page) and PAE's pointer entry. ARM64 levels use
    /// the `Arm64*` rules below, which read bit 1.
    TableOnly,
    /// Intel `PS` (bit 7) on a *hardware-present* entry ends the walk in a
    /// large page whose bit 12 is the high PAT index, not an address bit.
    /// The present-bit conjunct is load-bearing: a Windows transition entry
    /// has bit 7 set as `Protection` bit 2.
    IntelPageSize,
    /// The final Intel level: always a 4 KiB page, and bit 7 is the PAT
    /// index rather than a size flag.
    IntelPage,
    /// An ARM64 level where a block is permitted: bit 1 clear on a valid
    /// descriptor is a block (D8.3.1), bit 1 set a table.
    Arm64Block,
    /// The final ARM64 level: bit 1 set is a page; bit 1 clear is the
    /// reserved encoding, which the hardware treats as invalid.
    Arm64Page,
    /// An ARM64 level above the last where no feature of the architecture
    /// permits a block (a 16 KiB level 0): bit 1 set is a table; bit 1
    /// clear is reserved and invalid.
    Arm64TableOnly,
    /// An ARM64 level above the last where a block exists only under
    /// FEAT_LPA (64 KiB level 1) or FEAT_LPA2 (4 KiB level 0, 16 KiB level
    /// 1): bit 1 set is a table; bit 1 clear is a block this build does not
    /// decode or the reserved encoding, and nothing in the image says which,
    /// so it is [`EntryKind::Unnameable`] — refused, never absent.
    Arm64TableOrLpaBlock,
}

impl LeafRule {
    /// Whether a walk can end at a level under this rule.
    pub fn can_terminate(self) -> bool {
        !matches!(
            self,
            LeafRule::TableOnly | LeafRule::Arm64TableOnly | LeafRule::Arm64TableOrLpaBlock
        )
    }
}

/// What one entry, read at one level, is — the classifier's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// The convention in force will not follow it: not present, or a
    /// reserved encoding the hardware treats as invalid. Ask
    /// [`PagingSpec::classify_invalid`] what more can be said.
    Invalid,
    /// It names the next level's table.
    Table,
    /// It ends the walk in a page or block.
    Leaf {
        /// The frame's physical address, with the page offset bits zero.
        frame: u64,
        /// `log2` of the page or block size, which is also how many low
        /// virtual-address bits carry through unchanged.
        size_log2: u32,
        /// The entry's execute-never bit, as this mode reads it — bit 63 on
        /// Intel; on ARM64 the XN bit for the regime's own exception level
        /// (`UXN` under TTBR0, `PXN` under TTBR1). Reported as observed, not
        /// interpreted: see [`Translation::no_execute`].
        ///
        /// [`Translation::no_execute`]: crate::translate::Translation::no_execute
        no_execute: bool,
    },
    /// A present leaf whose frame this spec cannot state without guessing:
    /// PSE-36 bits in a 4 MiB Intel entry, FEAT_LPA/LPA2 output-address bits
    /// in an ARM64 descriptor. Refused rather than masked, because a masked
    /// frame is a confident address gigabytes from the truth.
    Unnameable { detail: &'static str },
}

/// One level of a paging structure, top-down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageLevel {
    /// How the level is named in Intel's manuals, for error messages an
    /// examiner has to read.
    pub name: &'static str,
    /// How many virtual-address bits index this level's table.
    pub index_bits: u32,
    /// How an entry **read from this level's table** is told apart into a
    /// table, a page or a block.
    ///
    /// [`LeafRule::TableOnly`] on an Intel top level (Intel defines no
    /// 512 GiB page; FEAT_LPA2's 4 KiB level-0 block is ARM64's and this
    /// build does not decode it) and [`LeafRule::IntelPage`] on the final one,
    /// where bit 7 is the PAT index: marking the final level
    /// [`LeafRule::IntelPageSize`] would turn every write-combining 4 KiB
    /// page into a bogus large page.
    pub leaf: LeafRule,
}

const INTEL32_LEVELS: &[PageLevel] = &[
    PageLevel {
        name: "page directory",
        index_bits: 10,
        leaf: LeafRule::IntelPageSize,
    },
    PageLevel {
        name: "page table",
        index_bits: 10,
        leaf: LeafRule::IntelPage,
    },
];

const PAE_LEVELS: &[PageLevel] = &[
    PageLevel {
        name: "page directory pointer table",
        index_bits: 2,
        leaf: LeafRule::TableOnly,
    },
    PageLevel {
        name: "page directory",
        index_bits: 9,
        leaf: LeafRule::IntelPageSize,
    },
    PageLevel {
        name: "page table",
        index_bits: 9,
        leaf: LeafRule::IntelPage,
    },
];

const INTEL32E_LEVELS: &[PageLevel] = &[
    PageLevel {
        name: "page map level 4",
        index_bits: 9,
        leaf: LeafRule::TableOnly,
    },
    PageLevel {
        name: "page directory pointer table",
        index_bits: 9,
        leaf: LeafRule::IntelPageSize,
    },
    PageLevel {
        name: "page directory",
        index_bits: 9,
        leaf: LeafRule::IntelPageSize,
    },
    PageLevel {
        name: "page table",
        index_bits: 9,
        leaf: LeafRule::IntelPage,
    },
];

/// The five-level (LA57) hierarchy: [`INTEL32E_LEVELS`] with a PML5 on top.
///
/// Written out rather than derived from the four-level table so that the whole
/// structure of a mode is readable in one place — the alternative, a shared
/// tail and a prepended level, hides the one thing that has to be checked,
/// which is that the index bits sum to the declared virtual width.
///
/// The PML5 honours no large page: Intel defines no 256 TiB page, and a PS bit
/// set at this level is reserved. Marking it large-page-capable would end a
/// walk at the top table and return the PML5's own frame as a colossal page.
const INTEL32E_LA57_LEVELS: &[PageLevel] = &[
    PageLevel {
        name: "page map level 5",
        index_bits: 9,
        leaf: LeafRule::TableOnly,
    },
    PageLevel {
        name: "page map level 4",
        index_bits: 9,
        leaf: LeafRule::TableOnly,
    },
    PageLevel {
        name: "page directory pointer table",
        index_bits: 9,
        leaf: LeafRule::IntelPageSize,
    },
    PageLevel {
        name: "page directory",
        index_bits: 9,
        leaf: LeafRule::IntelPageSize,
    },
    PageLevel {
        name: "page table",
        index_bits: 9,
        leaf: LeafRule::IntelPage,
    },
];

/// The most levels any mode walks: five, on LA57.
const MAX_LEVELS: usize = 5;

/// A mode's level list, held inline so an ARM64 regime — whose top level is
/// sized by `TxSZ` and is not one of a fixed set — can be derived in a
/// `const fn` without a static table per width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Levels {
    items: [PageLevel; MAX_LEVELS],
    len: usize,
}

/// A slot no mode reads: the padding behind `len`. Same in every spec, so
/// two specs with equal levels compare equal.
const UNUSED_LEVEL: PageLevel = PageLevel {
    name: "",
    index_bits: 0,
    leaf: LeafRule::TableOnly,
};

impl Levels {
    const fn from_static(levels: &'static [PageLevel]) -> Self {
        let mut items = [UNUSED_LEVEL; MAX_LEVELS];
        let mut i = 0;
        while i < levels.len() && i < MAX_LEVELS {
            items[i] = levels[i];
            i += 1;
        }
        Self {
            items,
            len: if levels.len() < MAX_LEVELS {
                levels.len()
            } else {
                MAX_LEVELS
            },
        }
    }

    fn as_slice(&self) -> &[PageLevel] {
        &self.items[..self.len]
    }
}

/// ARM's names for its levels, indexed by ARM level number. The last level
/// is always level 3; a narrower regime starts lower down.
const ARM64_LEVEL_NAMES: [&str; 4] = [
    "level 0 translation table",
    "level 1 translation table",
    "level 2 translation table",
    "level 3 translation table",
];

/// The level list of one ARM64 regime, from the granule and the VA width
/// (D8.2, "The VMSAv8-64 translation table format": the initial lookup
/// level is the highest level whose input bits fall inside the region).
///
/// Below the page offset, each full table indexes `page_shift - 3` bits
/// (512, 2048 or 8192 entries); the top table indexes whatever is left of
/// the width, which is why a 4 KiB, 39-bit regime has three 512-entry levels
/// and a 16 KiB, 48-bit one has a two-entry level 0 above three full ones.
const fn arm64_levels(granule: Arm64Granule, va_bits: u8, lpa2: bool) -> Levels {
    let page_shift = granule.page_shift();
    let per_level = granule.index_bits();
    // `Arm64Regime::new` bounds the width at 25..=48, so this never
    // underflows; the saturation keeps a malformed regime from panicking.
    let to_index = (va_bits as u32).saturating_sub(page_shift);
    // ceil(to_index / per_level), at least one level.
    let mut count = to_index.div_ceil(per_level);
    if count == 0 {
        count = 1;
    }
    if count > 4 {
        count = 4;
    }
    let top_bits = to_index - per_level * (count - 1);
    let first_arm_level = 4 - count;
    let mut items = [UNUSED_LEVEL; MAX_LEVELS];
    let mut i = 0;
    while i < count {
        let arm_level = first_arm_level + i;
        let last = i + 1 == count;
        let leaf = if last {
            LeafRule::Arm64Page
        } else if granule.block_permitted_at(arm_level) {
            LeafRule::Arm64Block
        } else if lpa2 && granule.block_permitted_only_under_lpa(arm_level) {
            // FEAT_LPA2 is on: a 16 KiB level-1 descriptor with the type bit
            // clear is the 64 GiB block it permits, not an undecodable one.
            LeafRule::Arm64Block
        } else if granule.block_permitted_only_under_lpa(arm_level) {
            LeafRule::Arm64TableOrLpaBlock
        } else {
            LeafRule::Arm64TableOnly
        };
        items[i as usize] = PageLevel {
            name: ARM64_LEVEL_NAMES[arm_level as usize],
            index_bits: if i == 0 { top_bits } else { per_level },
            leaf,
        };
        i += 1;
    }
    Levels {
        items,
        len: count as usize,
    }
}

/// Bits of virtual address consumed by the final page offset in every Intel
/// mode, and the unit Windows pages in. An ARM64 regime's page offset is its
/// granule's — ask [`PagingSpec::page_offset_bits`] rather than this.
pub const PAGE_OFFSET_BITS: u32 = 12;

/// Why an entry the hardware would reject is rejected, as far as the software
/// convention in force can tell.
///
/// The three cases are *different forensic facts*, and the whole reason
/// [`PteSemantics`] exists is to keep them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidEntry {
    /// Nothing is claimed beyond "the hardware would fault here". The page is
    /// not resident and this convention cannot say where it went.
    NotPresent,
    /// A Windows prototype PTE: the page belongs to a section (a mapped file or
    /// shared memory) and its real state is in a `_SUBSECTION` / `_CONTROL_AREA`
    /// chain. Resolving it needs the object model, not the page tables, so the
    /// walk stops here and says exactly that.
    Prototype,
    /// A Windows software PTE naming a location in a pagefile. The bytes exist
    /// on the suspect's disk and are simply not in this evidence item.
    PageFile {
        /// Which pagefile (`MMPTE_SOFTWARE.PageFileLow`, bits 4:1).
        ///
        /// Windows 8 moved that field to bits 15:12, and no image publishes its
        /// build, so this is the pre-Windows-8 reading of bits an examiner
        /// should be told the provenance of rather than shown as certain.
        /// Which pagefile, when the build settled where that field lives.
        /// `None` means the layout was never established and no number is
        /// claimed — see [`PagingSpec::with_win8_pagefile_layout`]. ARM64
        /// Windows always yields `None`, a decided limit rather than an
        /// unknown build, so no swapped page there resolves through a
        /// pagefile.
        index: Option<u8>,
        /// The page's index within that pagefile
        /// (`MMPTE_SOFTWARE.PageFileHigh`). Multiply by 4 KiB to get a byte
        /// offset: Windows pages in 4 KiB units at every level, so a software
        /// entry above the final level names the 4 KiB paging structure that
        /// was paged out, not a region-sized block.
        page_number: u64,
    },
    /// A Linux `swp_entry_t`: an entry that is neither empty nor `PROT_NONE`,
    /// so the kernel moved this page's contents out of its frame and recorded
    /// where.
    ///
    /// Deliberately field-less. The area and the page within it are there in
    /// the entry, and every bit position that would read them is a property of
    /// the kernel source rather than of the machine, with no fact in the image
    /// to select between the layouts — see [`PteSemantics::Linux`]. The raw
    /// entry travels on the error the walk produces, so an examiner who knows
    /// which kernel this was can decode it by hand; what this crate will not do
    /// is decode it *for* them out of a layout it picked.
    ///
    /// It is also not exclusively a swap **file** location: a migration entry,
    /// a hardware-poison marker and a device-private entry all live in the same
    /// encoding. That is the second reason nothing here says "this page is in
    /// swap slot *n*".
    LinuxSwapEntry,
}

/// Keep bits `[low, high]` of `value`, **in place**, inclusive at both ends.
///
/// This is the one primitive the whole walk is built from, and both ends being
/// inclusive is the transcription detail most often got wrong: a mask written
/// with an exclusive high bound drops the top physical-address bit, which moves
/// every translated address in the upper half of a large memory image without
/// making any of them look wrong.
///
/// Returns `0` rather than panicking on a nonsensical range, so a malformed
/// spec can never take the process down with it.
pub fn mask_bits(value: u64, high: u32, low: u32) -> u64 {
    if low >= 64 || high < low {
        return 0;
    }
    let high_mask = if high >= 63 {
        u64::MAX
    } else {
        (1u64 << (high + 1)) - 1
    };
    let low_mask = (1u64 << low) - 1;
    value & (high_mask ^ low_mask)
}

/// The output address a FEAT_LPA2 descriptor (`TCR_EL1.DS = 1`, 16 KiB granule)
/// names, with the bits below `low` cleared: bits 47:`low` and 49:48 as they
/// stand, and bits 9:8 (shareability without `DS`) as address bits 51:50
/// (ARM DDI 0487 D8.3, "Output address").
pub(crate) fn arm64_lpa2_output_address(entry: u64, low: u32) -> u64 {
    mask_bits(entry, 49, low) | (((entry >> 8) & 0b11) << 50)
}

/// Everything the walker needs to know about one paging mode under one set of
/// OS conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagingSpec {
    mode: PagingMode,
    semantics: PteSemantics,
    entry_size: u32,
    entry_size_log2: u32,
    bits_per_register: u32,
    max_virt_addr_bits: u32,
    max_phys_addr_bits: u32,
    swap_bit_offset: u32,
    /// Bit position of `MMPTE_SOFTWARE.PageFileLow`, the field naming WHICH
    /// pagefile a swapped-out page went to.
    ///
    /// It sat at bits 4:1 up to Windows 7 and moved to bits 15:12 on Windows 8
    /// and later, where bits 4:1 became `PageFileReserved`, `PageFileAllocated`,
    /// `ColdPage` and `SwizzleBit`. Decoding the wrong ones does not fail — it
    /// yields a plausible small integer that is a different pagefile's number,
    /// which is the kind of wrong answer this crate exists to avoid. `None`
    /// means the build was never established, and the index is then not
    /// reported at all rather than guessed.
    swap_index_shift: Option<u32>,
    levels: Levels,
}

impl PagingSpec {
    /// The parameters for one (mode, OS) cell.
    ///
    /// MAXPHYADDR and the swap bit offset are looked up **per cell** rather
    /// than per mode or per OS, because they genuinely differ that way:
    ///
    /// | | MAXPHYADDR | swap bit offset |
    /// |---|---|---|
    /// | 32-bit, any OS | 32 | 12 (`MMPTE_SOFTWARE.PageFileHigh` starts at bit 12 in a 4-byte PTE) |
    /// | PAE, any OS | 40 | 32 |
    /// | x64 (four- or five-level), bare or Linux | 52 | 32 |
    /// | x64 (four- or five-level), Windows | **45** | 32 |
    ///
    /// The 45 exists because Windows stores software state in x64 entry bits
    /// 45..51. Applying it to the 32-bit or PAE cells — the mistake a
    /// "Windows-ness" mixin invites — would widen those masks past the
    /// architectural width and produce wrong addresses.
    ///
    /// # ARM64
    ///
    /// The entry is eight bytes and the output address is read as 48 bits
    /// (D8.3.1: bits 47:n of a descriptor, n the page or block shift). That
    /// is the width without FEAT_LPA/LPA2; the bits those features press
    /// into service — 49:48 for a 4 KiB or 16 KiB granule, 15:12 for 64 KiB
    /// — are checked and a descriptor using them is refused, since whether
    /// the feature is on is `TCR_EL1.DS`, which no image records. The block
    /// levels those features add (4 KiB level 0, 16 KiB level 1, 64 KiB
    /// level 1) are refused the same way rather than read as absent — see
    /// [`Arm64Granule::block_permitted_at`]. The
    /// Windows narrowing does not apply: it was read out of x64 entries. The ARM64 Windows
    /// software-PTE conventions (transition, prototype, pagefile) were read from the PDB of
    /// build 28000 and checked on its capture (`MEM-ARM-8`), and are those of one build.
    pub const fn new(mode: PagingMode, semantics: PteSemantics) -> Self {
        let (entry_size, entry_size_log2, bits_per_register, max_virt_addr_bits, levels) =
            match mode {
                PagingMode::Intel32 => (
                    4u32,
                    2u32,
                    32u32,
                    32u32,
                    Levels::from_static(INTEL32_LEVELS),
                ),
                PagingMode::IntelPae => (8, 3, 32, 32, Levels::from_static(PAE_LEVELS)),
                PagingMode::Intel32e => (8, 3, 64, 48, Levels::from_static(INTEL32E_LEVELS)),
                PagingMode::Intel32eLa57 => {
                    (8, 3, 64, 57, Levels::from_static(INTEL32E_LA57_LEVELS))
                }
                PagingMode::Arm64(regime) => (
                    8,
                    3,
                    64,
                    regime.va_bits as u32,
                    arm64_levels(regime.granule, regime.va_bits, regime.lpa2),
                ),
            };
        let max_phys_addr_bits = match (mode, semantics) {
            (PagingMode::Intel32, _) => 32u32,
            (PagingMode::IntelPae, _) => 40,
            // LA57 widens the *virtual* space and leaves the entry format
            // alone: an LA57 entry is an x64 entry, so every physical width
            // below is the four-level one.
            (
                PagingMode::Intel32e | PagingMode::Intel32eLa57,
                PteSemantics::Bare | PteSemantics::Linux,
            ) => 52,
            (PagingMode::Intel32e | PagingMode::Intel32eLa57, PteSemantics::Windows) => 45,
            (PagingMode::Arm64(regime), _) if regime.lpa2 => 52,
            (PagingMode::Arm64(_), _) => 48,
        };
        let swap_bit_offset = match mode {
            PagingMode::Intel32 => 12u32,
            PagingMode::IntelPae | PagingMode::Intel32e | PagingMode::Intel32eLa57 => 32,
            // `MMPTE_SOFTWARE.PageFileHigh` of Windows 11 ARM64 build 28000 (Microsoft's
            // PDB), bits 63:32. Other conventions on ARM64 name no pagefile.
            PagingMode::Arm64(_) if matches!(semantics, PteSemantics::Windows) => 32,
            PagingMode::Arm64(_) => 64,
        };
        Self {
            mode,
            semantics,
            entry_size,
            entry_size_log2,
            bits_per_register,
            max_virt_addr_bits,
            max_phys_addr_bits,
            swap_bit_offset,
            // Unknown until a caller states the build. Defaulting to either
            // layout would make the common case silently wrong on half of all
            // Windows versions.
            swap_index_shift: None,
            levels,
        }
    }

    /// The paging structure this spec describes.
    pub fn mode(&self) -> PagingMode {
        self.mode
    }

    /// The convention governing non-present entries.
    pub fn semantics(&self) -> PteSemantics {
        self.semantics
    }

    /// Size of one paging entry in bytes: 4 for 32-bit non-PAE, 8 otherwise.
    pub fn entry_size(&self) -> u32 {
        self.entry_size
    }

    /// `log2(entry_size)`, the shift that turns a table index into a byte
    /// offset and half of the table-alignment mask.
    pub fn entry_size_log2(&self) -> u32 {
        self.entry_size_log2
    }

    /// Width of the machine's general registers, 32 or 64. The only thing it
    /// decides here is whether virtual addresses are sign-extended
    /// (canonical-form checking) or simply truncated.
    pub fn bits_per_register(&self) -> u32 {
        self.bits_per_register
    }

    /// How many virtual-address bits the paging structure actually translates.
    pub fn max_virt_addr_bits(&self) -> u32 {
        self.max_virt_addr_bits
    }

    /// The highest physical-address bit an entry may contribute, exclusive
    /// upper bound in bit count (so `52` means bits 51:0).
    pub fn max_phys_addr_bits(&self) -> u32 {
        self.max_phys_addr_bits
    }

    /// Bit position at which a Windows software PTE stores the page's index
    /// within its pagefile.
    pub fn swap_bit_offset(&self) -> u32 {
        self.swap_bit_offset
    }

    /// State which `MMPTE_SOFTWARE.PageFileLow` layout this image uses.
    ///
    /// `true` selects the Windows 8-and-later position (bits 15:12), `false`
    /// the earlier one (bits 4:1). The argument is ignored on ARM64, where the
    /// field's position differs between builds and no index is ever stated.
    /// A spec that is never told stays silent about
    /// the pagefile index rather than reporting one from whichever bits it
    /// happened to read.
    ///
    /// Take the argument from [`KernelBuild::is_win8_or_later`], which returns
    /// `Option<bool>` precisely so that "the build was never established"
    /// cannot be mistaken for "not Windows 8".
    ///
    /// [`KernelBuild::is_win8_or_later`]: https://docs.rs/seance_plugin_memory_windows
    pub fn with_win8_pagefile_layout(mut self, win8_or_later: bool) -> Self {
        self.swap_index_shift = if !self.mode.is_intel() {
            // `PageFileLow` is not at one place on ARM64 Windows: bits 17:14 on build 28000 and bits 9:6 on
            // build 26300.9457 (each build's own PDB, `MEM-ARM-8` and `MEM-ARM-11`), and a spec is not told
            // the build. A pagefile index read from either place is wrong on the other build, and on 26300 it
            // named pagefile 0 for entries whose own field says 1. So no index is stated on ARM64, as on an
            // x64 image of unknown build; `PageFileHigh` (bits 63:32) agrees on both and is still reported.
            None
        } else {
            Some(if win8_or_later { 12 } else { 1 })
        };
        self
    }

    /// The `PageFileLow` bit position, when the build settled it.
    pub fn swap_index_shift(&self) -> Option<u32> {
        self.swap_index_shift
    }

    /// The levels of this structure, top-down.
    pub fn levels(&self) -> &[PageLevel] {
        self.levels.as_slice()
    }

    /// The name the architecture gives level `index`, for an error an
    /// examiner reads.
    pub fn level_name(&self, index: usize) -> Option<&'static str> {
        self.levels().get(index).map(|l| l.name)
    }

    /// Bits of virtual address the smallest page carries: 12 on Intel, the
    /// granule's shift on ARM64.
    pub fn page_offset_bits(&self) -> u32 {
        match self.mode {
            PagingMode::Arm64(regime) => regime.granule.page_shift(),
            _ => PAGE_OFFSET_BITS,
        }
    }

    /// The ARM64 regime this spec describes, when it is one.
    fn arm64(&self) -> Option<Arm64Regime> {
        self.mode.arm64()
    }

    /// The lowest virtual address in this mode's space.
    ///
    /// Zero for every mode but an ARM64 TTBR1 regime, whose space is the top
    /// `2^va_bits` bytes of the 64-bit space and nothing below them: an
    /// address below that base belongs to TTBR0 and is not this regime's to
    /// translate.
    pub fn min_virtual_address(&self) -> u64 {
        match self.arm64() {
            Some(regime) if regime.ttbr == Ttbr::Ttbr1 => self.ttbr1_base(),
            _ => 0,
        }
    }

    /// The highest virtual address in this mode's space.
    ///
    /// For a sign-extending mode that is `u64::MAX`, not `2^48 - 1`: the upper
    /// canonical half — where every operating system puts its kernel — runs all
    /// the way to the top of the 64-bit space. The unusable middle is rejected
    /// by [`PagingSpec::is_canonical`], not by clamping the maximum.
    ///
    /// An ARM64 TTBR0 regime ends at `2^va_bits - 1`: the addresses above it
    /// are TTBR1's or nobody's, and neither is this regime's to translate.
    pub fn max_virtual_address(&self) -> u64 {
        if let Some(regime) = self.arm64() {
            return match regime.ttbr {
                Ttbr::Ttbr0 => (1u64 << self.max_virt_addr_bits) - 1,
                Ttbr::Ttbr1 => u64::MAX,
            };
        }
        if self.bits_per_register >= 64 || self.max_virt_addr_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << self.max_virt_addr_bits) - 1
        }
    }

    /// The first address of an ARM64 TTBR1 regime: every bit from `va_bits`
    /// up set, everything below clear.
    fn ttbr1_base(&self) -> u64 {
        if self.max_virt_addr_bits >= 64 {
            return 0;
        }
        u64::MAX << self.max_virt_addr_bits
    }

    /// Whether the hardware would accept `va` as an address at all.
    ///
    /// On x86-64 the bits above the translated width are not ignored: they must
    /// all repeat bit 47, and a CPU faults on any address that does not. An
    /// address like `0x0000_8000_0000_0000` therefore has no meaning, and a
    /// walker that masks it down to 47 bits instead of rejecting it invents a
    /// translation for an address the machine could never have issued —
    /// typically turning a corrupt pointer into a confident, wrong answer.
    ///
    /// In the 32-bit modes there is no sign extension: an address is valid iff
    /// it fits in 32 bits.
    ///
    /// # ARM64: canonical *for this regime*
    ///
    /// The hardware selects the root by the address's upper bits (D8.2.3:
    /// bits 63:`va_bits` all zero select `TTBR0_EL1`, all one `TTBR1_EL1`,
    /// anything else faults), so an address is canonical for a TTBR1 spec
    /// only when those bits are all one, and for a TTBR0 spec only when
    /// they are all zero. A lower-half address handed to the kernel's layer
    /// is refused, not walked through the kernel's tables to a wrong page.
    ///
    /// Top-byte-ignore (`TCR_EL1.TBI0`/`TBI1`, D8.8) is honoured when the
    /// regime records it — only a regime built by
    /// [`Arm64Regime::from_tcr_el1`] from a `TCR_EL1` whose bit for this
    /// TTBR is set. Then bits 63:56 are ignored and bits 55:`va_bits` still
    /// select the regime, so a tagged pointer is canonical exactly when its
    /// untagged form is, and the walk (which indexes only the low `va_bits`)
    /// translates it identically. A regime built by [`Arm64Regime::new`]
    /// never untags: whether TBI was on is register state, and without it a
    /// tagged pointer is reported as non-canonical, not silently untagged.
    pub fn is_canonical(&self, va: u64) -> bool {
        if let Some(regime) = self.arm64() {
            if self.arm64_strictly_canonical(regime, va) {
                return true;
            }
            if !regime.tbi {
                return false;
            }
            let untagged = match regime.ttbr {
                Ttbr::Ttbr0 => va & !ARM64_TAG_MASK,
                Ttbr::Ttbr1 => va | ARM64_TAG_MASK,
            };
            return self.arm64_strictly_canonical(regime, untagged);
        }
        if self.max_virt_addr_bits >= 64 {
            return true;
        }
        if self.bits_per_register < 64 {
            return va >> self.max_virt_addr_bits == 0;
        }
        // Saturating so that no spec, however malformed, can turn a bounds
        // check into an arithmetic panic.
        let sign_bit = self.max_virt_addr_bits.saturating_sub(1);
        let sign = va >> sign_bit;
        sign == 0 || sign == u64::MAX >> sign_bit
    }

    /// Whether `va`, taken whole with no top byte ignored, lies in this ARM64
    /// regime's half of the space.
    fn arm64_strictly_canonical(&self, regime: Arm64Regime, va: u64) -> bool {
        if self.max_virt_addr_bits >= 64 {
            return true;
        }
        let upper = va >> self.max_virt_addr_bits;
        match regime.ttbr {
            Ttbr::Ttbr0 => upper == 0,
            Ttbr::Ttbr1 => upper == u64::MAX >> self.max_virt_addr_bits,
        }
    }

    /// The lowest canonical address at or above `va`, or `None` when every
    /// address from `va` up is one the hardware would fault on.
    ///
    /// For a sign-extending mode this jumps the unusable middle: an address in
    /// it answers with the base of the **upper** canonical half, which is where
    /// every operating system puts its kernel. A walk that treated the middle
    /// as the end of the space would enumerate the lower half and stop, and
    /// [`is_canonical`](PagingSpec::is_canonical) alone cannot tell a caller
    /// where to resume.
    ///
    /// On ARM64 the answer is always in the **untagged** space, TBI or not:
    /// a tagged pointer is an alias of an untagged one, and resuming a walk
    /// at an alias would report the same pages twice under another name.
    pub fn next_canonical(&self, va: u64) -> Option<u64> {
        if let Some(regime) = self.arm64() {
            if self.arm64_strictly_canonical(regime, va) {
                return Some(va);
            }
            // A TTBR0 regime has nothing above its top; a TTBR1 regime has
            // nothing below its base, and everything from the base up.
            return match regime.ttbr {
                Ttbr::Ttbr0 => None,
                Ttbr::Ttbr1 => {
                    let base = self.ttbr1_base();
                    (va < base).then_some(base)
                }
            };
        }
        if self.is_canonical(va) {
            return Some(va);
        }
        if self.bits_per_register < 64 {
            // No sign extension: everything above the width is simply past the
            // top of the space.
            return None;
        }
        let sign_bit = self.max_virt_addr_bits.saturating_sub(1);
        if sign_bit >= 64 {
            return None;
        }
        // The upper canonical half begins where every bit from the sign bit up
        // is set.
        let upper = u64::MAX << sign_bit;
        (va < upper).then_some(upper)
    }

    /// The part of `va` that indexes the tables: the low
    /// [`max_virt_addr_bits`](PagingSpec::max_virt_addr_bits) bits, with the
    /// sign extension of a canonical address removed.
    pub fn index_source(&self, va: u64) -> u64 {
        mask_bits(va, self.max_virt_addr_bits.saturating_sub(1), 0)
    }

    /// Whether the walker may follow this entry.
    ///
    /// Under [`PteSemantics::Windows`] a transition entry counts as usable even
    /// though the hardware would fault on it, because the frame it names is
    /// still in RAM and still holds the page's bytes. That is a deliberate
    /// recovery of standby-list evidence, not a relaxation of the present bit.
    pub fn entry_is_present(&self, entry: u64) -> bool {
        if (entry & PRESENT_BIT) != 0 {
            return true;
        }
        // No convention beyond the valid bit is applied to an ARM64
        // descriptor. Windows' transition layout was read out of x64
        // entries, and reading bits 10 and 11 of an ARM64 descriptor as
        // `Transition` and `Prototype` would follow the access flag and the
        // not-global bit into a frame.
        if !self.mode.is_intel() {
            // Windows ARM64 (`_MMPTE_TRANSITION`, build 28000's PDB) keeps `Prototype` at
            // bit 10 and `Transition` at bit 11 of an entry whose valid bit is clear, the
            // same places as x64. Only a descriptor with the valid bit CLEAR is read this
            // way; on a valid one those bits stay the access flag and nG.
            return self.semantics == PteSemantics::Windows
                && (entry & WINDOWS_TRANSITION_BIT) != 0
                && (entry & WINDOWS_PROTOTYPE_BIT) == 0;
        }
        match self.semantics {
            PteSemantics::Bare => false,
            // Linux calls a `_PAGE_PROTNONE` entry present, and it is not
            // followed here: the hardware faults on it, and since the L1TF
            // mitigation its frame number is stored inverted, so the frame this
            // walk would extract is not the frame the kernel holds. Refusing it
            // costs a `PROT_NONE` page — which the process could not read
            // either — and avoids answering with somebody else's memory.
            PteSemantics::Linux => false,
            PteSemantics::Windows => {
                (entry & WINDOWS_TRANSITION_BIT) != 0 && (entry & WINDOWS_PROTOTYPE_BIT) == 0
            }
        }
    }

    /// Say as much as the convention in force honestly supports about an entry
    /// [`entry_is_present`](PagingSpec::entry_is_present) rejected.
    ///
    /// Never guesses: under [`PteSemantics::Bare`] the answer is always
    /// [`InvalidEntry::NotPresent`], because a bare walker has no basis for
    /// claiming a pagefile location, and claiming one anyway would put a
    /// fabricated disk offset in a report.
    ///
    /// Under [`PteSemantics::Linux`] the answer separates "never mapped" from
    /// "the kernel moved this page's contents out", which is as far as Linux's
    /// version-independent predicates reach, and stops there — see that variant
    /// for why the location inside the entry is not decoded.
    pub fn classify_invalid(&self, entry: u64) -> InvalidEntry {
        if !self.mode.is_intel() && self.semantics != PteSemantics::Windows {
            // Nothing is claimed about a non-valid ARM64 descriptor beyond
            // its absence, under any convention.
            //
            // Under Linux the honest floor is lower than on x86-64. There,
            // `_PAGE_PROTNONE` is a fixed bit and everything else non-empty
            // is a `swp_entry_t`; on arm64 the marker Linux uses for "the
            // kernel counts this present, the hardware faults" has moved —
            // `PTE_PROT_NONE` at bit 58 in older kernels, `PTE_PRESENT_INVALID`
            // aliased onto bit 11 (`PTE_NG`) in the 7.0 headers this was
            // checked against (`arch/arm64/include/asm/pgtable-prot.h`) — and
            // each of those positions is a swap-offset bit under the other
            // layout (`__SWP_OFFSET_SHIFT` 8 then 12, 50 bits wide). No
            // version-free predicate separates a `PROT_NONE` page from a
            // page the kernel moved out, so neither is asserted: a report
            // saying "contents moved out" of a page that was never written
            // anywhere is the wrong direction to be wrong in. The entry
            // travels verbatim on the error for an examiner who knows the
            // kernel.
            //
            // Under Windows the layout was read out of the PDB of the ARM64 kernel
            // build 28000 and checked on its capture (`MEM-ARM-8`): handled below.
            return InvalidEntry::NotPresent;
        }
        match self.semantics {
            PteSemantics::Bare => InvalidEntry::NotPresent,
            PteSemantics::Linux => {
                // `pte_none()`. The accessed and dirty bits are masked off
                // because Linux masks them off: some processors set them on an
                // entry the hardware would reject, and an entry that holds
                // nothing else is empty however they came to be set. Counting
                // one as a swap-family entry would report a page that was never
                // mapped as one whose contents the kernel put somewhere.
                if (entry & !LINUX_EMPTY_ENTRY_IGNORED_BITS) == 0 {
                    return InvalidEntry::NotPresent;
                }
                // `pte_present()` counts `_PAGE_PROTNONE`. A `PROT_NONE` or
                // NUMA-hinting entry names a frame the kernel still holds and
                // nothing in any swap area, so it must not join the bucket
                // below. Reported as plain absence, which understates it by the
                // frame this spec cannot state — the inverted-frame problem is
                // the same one that stops the swap decode.
                if (entry & LINUX_PROTNONE_BIT) != 0 {
                    return InvalidEntry::NotPresent;
                }
                // Everything else non-present is a `swp_entry_t`. Exactly one
                // claim is made about it, and it is the claim that holds under
                // every x86-64 kernel: this page had contents and they are not
                // in this image.
                //
                // The one entry this understates is a pre-Linux-4.0 nonlinear
                // file PTE (`remap_file_pages`) whose page offset is zero,
                // which is bit 6 alone and reads as empty above. Understating
                // is the safe direction, and `remap_file_pages` was removed in
                // 4.0; overstating would need this to treat a spuriously
                // dirty-flagged empty entry on every modern kernel as a moved
                // page.
                InvalidEntry::LinuxSwapEntry
            }
            PteSemantics::Windows => {
                if (entry & WINDOWS_PROTOTYPE_BIT) != 0 {
                    return InvalidEntry::Prototype;
                }
                if (entry & WINDOWS_TRANSITION_BIT) != 0 {
                    // A transition entry with the prototype bit clear is usable
                    // memory under these semantics, so the walker never asks
                    // about one. A direct caller that does gets plain absence:
                    // the bits a software PTE would use are a frame number
                    // here, and decoding them would fabricate a disk offset.
                    return InvalidEntry::NotPresent;
                }
                // MMPTE_SOFTWARE: Valid:1, PageFileLow:4, Protection:5,
                // Prototype:1, Transition:1, ..., PageFileHigh at
                // `swap_bit_offset`. A zero PageFileHigh names no location, so
                // there is nothing to report but absence.
                let page_number = if self.swap_bit_offset >= 64 {
                    0
                } else {
                    entry >> self.swap_bit_offset
                };
                if page_number == 0 {
                    return InvalidEntry::NotPresent;
                }
                InvalidEntry::PageFile {
                    // Only reported when the build settled which bits hold it.
                    // Reading bits 4:1 on a Windows 8+ image yields a small
                    // plausible integer that is a DIFFERENT pagefile's number,
                    // and a report naming the wrong pagefile is worse than one
                    // naming none.
                    index: self
                        .swap_index_shift
                        .map(|shift| ((entry >> shift) & WINDOWS_PAGEFILE_INDEX_MASK) as u8),
                    page_number,
                }
            }
        }
    }

    /// The kernel virtual address of the prototype `_MMPTE` a prototype PTE
    /// points at, when this spec can state it without guessing.
    ///
    /// # What an examiner learns
    ///
    /// A prototype PTE says "the real state of this page lives elsewhere". The
    /// address returned here is that elsewhere: an entry in the section
    /// object's prototype PTE array, in paged pool, which is mapped into every
    /// process's address space and therefore reachable through the same page
    /// tables. Following it is what turns a shared or file-backed page — a DLL's
    /// code, a mapped data file, a section shared between processes — from an
    /// apparent hole into the bytes that were resident all along.
    ///
    /// # What a wrong answer would look like
    ///
    /// A plausible kernel address pointing at bytes that are not a `_MMPTE` at
    /// all, decoded as a frame number, read as a page of somebody else's memory
    /// and attributed to this virtual address. Nothing about it would look
    /// wrong. So `None` is returned rather than a guess whenever:
    ///
    /// - the mode is 32-bit non-PAE, whose `MMPTE_PROTOTYPE` splits
    ///   `ProtoAddress` across a low and a high field whose widths and base
    ///   moved between builds;
    /// - the field is all ones (`MI_PTE_LOOKUP_NEEDED`), which means Windows
    ///   itself does not keep the address in the entry and recomputes it from
    ///   the VAD's subsection chain — an object the page tables cannot supply;
    /// - the field is zero, which names no array.
    ///
    /// Canonical form needs no check of its own: the x64 field is 48 signed
    /// bits, so every value it can hold sign-extends to a canonical address by
    /// construction, and the PAE field is 32 bits in a 32-bit space.
    pub fn prototype_address(&self, entry: u64) -> Option<u64> {
        if self.semantics != PteSemantics::Windows {
            return None;
        }
        let (va, lookup_needed) = match self.mode {
            // LA57 does not change `MMPTE_PROTOTYPE`: the entry is an x64
            // entry either way, and `ProtoAddress` is the same signed 48-bit
            // field at bits 63:16.
            PagingMode::Intel32e | PagingMode::Intel32eLa57 => (
                ((entry as i64) >> WINDOWS_X64_PROTO_ADDRESS_SHIFT) as u64,
                u64::MAX,
            ),
            PagingMode::IntelPae => (entry >> WINDOWS_PAE_PROTO_ADDRESS_SHIFT, 0xFFFF_FFFF),
            // The 32-bit layout splits the field across builds; the ARM64
            // layout has not been read out of any entry at all.
            PagingMode::Intel32 | PagingMode::Arm64(_) => return None,
        };
        if va == 0 || va == lookup_needed {
            return None;
        }
        Some(va)
    }

    /// How far to shift `index_source` to read level `level`'s index, which is
    /// also the number of address bits the *page* ending at that level carries.
    ///
    /// `None` for a level this mode has not.
    fn index_shift(&self, level: usize) -> Option<u32> {
        let mut remaining = self.max_virt_addr_bits;
        for (depth, page_level) in self.levels().iter().enumerate() {
            remaining = remaining.checked_sub(page_level.index_bits)?;
            if depth == level {
                return Some(remaining);
            }
        }
        None
    }

    /// The index level `level` takes out of `va`, `0` being the top table.
    ///
    /// The forward half of [`virtual_address_from_indices`]. The walk computes
    /// this inline as it descends; published here so a caller that has to
    /// decompose an address — a reverse mapping checking its own
    /// reconstruction, a test pinning the round trip — uses the same
    /// arithmetic the walk does rather than a second copy of it.
    ///
    /// `None` for a level this mode has not.
    pub fn index_at(&self, va: u64, level: usize) -> Option<u64> {
        let shift = self.index_shift(level)?;
        let bits = self.levels().get(level)?.index_bits;
        if bits >= 64 {
            return None;
        }
        Some((self.index_source(va) >> shift) & ((1u64 << bits) - 1))
    }

    /// How many address bits the entry at level `level` governs.
    ///
    /// Read two ways, and it is deliberately the same number both times:
    ///
    /// * where a walk **can** end at this level, it is the page's offset
    ///   width — 12 at a final level, 21 or 30 for an x64 large page, 22 for a
    ///   4 MiB one — and therefore `log2` of [`Translation::run_len`]. That is
    ///   how a downward enumeration states a run length without deriving one
    ///   of its own.
    /// * where a walk **cannot** — an `Intel32e` PML4 entry, PAE's
    ///   page-directory-pointer entry — it is the size of the region that
    ///   entry governs: 512 GiB and 1 GiB respectively. That is the number an
    ///   *absent* entry needs, because a not-present PML4 entry means 512 GiB
    ///   of address space is absent and a caller recording the hole records
    ///   that span.
    ///
    /// So it is **not** named for a page: asking
    /// [`terminates_at`](PagingSpec::terminates_at) is what says whether a
    /// page can end here, and a caller that prints this as a page size
    /// without asking would publish a 512 GiB page.
    ///
    /// `None` for a level this mode has not.
    ///
    /// [`Translation::run_len`]: crate::translate::Translation::run_len
    pub fn region_bits_at(&self, level: usize) -> Option<u32> {
        self.index_shift(level)
    }

    /// Whether a walk can end at level `level` — that is, whether an entry
    /// read from this level's table can describe a page rather than another
    /// table.
    ///
    /// True at the final level always, and earlier exactly where the level
    /// declares itself large-page-capable. False on an Intel top level, since
    /// Intel defines no 512 GiB page (FEAT_LPA2 does, on ARM64's 4 KiB
    /// level 0, and this build does not decode it), and false on PAE's
    /// page-directory-pointer level, which has no page size of its own.
    ///
    /// `None` for a level this mode has not.
    pub fn terminates_at(&self, level: usize) -> Option<bool> {
        let page_level = self.levels().get(level)?;
        Some(page_level.leaf.can_terminate())
    }

    /// What `entry`, read from level `level`'s table, is under this spec.
    ///
    /// The one place the walk and the enumeration decide "table, page, block
    /// or nothing", and the one place a frame is extracted from an entry.
    /// Both walkers ask it, so they cannot disagree, and each level's
    /// [`LeafRule`] states what it reads:
    ///
    /// * Intel: `PS` (bit 7) on a hardware-present entry at a level that
    ///   permits it ends the walk in a large page whose bit 12 is the high
    ///   PAT index and is cleared before the frame is read; the final level
    ///   is always a 4 KiB page, and bit 7 there is the PAT index. A 4 MiB
    ///   32-bit entry carrying PSE-36 bits is
    ///   [`EntryKind::Unnameable`], since this spec's 32-bit physical width
    ///   cannot express the frame it names.
    /// * ARM64 (D8.3.1): bit 1 on a valid descriptor separates a table (set)
    ///   from a block (clear) above the last level, and a page (set) from
    ///   the reserved encoding (clear) at it. A block at a level no feature
    ///   permits one is that reserved encoding too; a block at a level only
    ///   FEAT_LPA or FEAT_LPA2 permits one (4 KiB level 0, 16 KiB level 1,
    ///   64 KiB level 1) is [`EntryKind::Unnameable`], because the image
    ///   does not say whether the feature was on and "not present" would be
    ///   a claim as unfounded as a frame. The output address is bits 47:n; a
    ///   descriptor with FEAT_LPA/LPA2 output bits set is
    ///   [`EntryKind::Unnameable`], and so is one — table or leaf — whose
    ///   output address is above the regime's `TCR_EL1.IPS` width (an
    ///   Address size fault, D8.5; 48 bits when no `TCR_EL1` was recorded).
    ///
    /// The frame is masked from `max_phys_addr_bits - 1` down to the bits the
    /// page carries, both ends inclusive, and never from a fixed 12.
    ///
    /// `None` for a level this mode has not.
    pub fn classify(&self, entry: u64, level: usize) -> Option<EntryKind> {
        let page_level = self.levels().get(level)?;
        let remaining = self.index_shift(level)?;
        if !self.entry_is_present(entry) {
            return Some(EntryKind::Invalid);
        }
        let phys_high = self.max_phys_addr_bits.checked_sub(1)?;
        let hardware_present = (entry & PRESENT_BIT) != 0;
        let (frame_source, no_execute) = match page_level.leaf {
            LeafRule::TableOnly => return Some(EntryKind::Table),
            LeafRule::IntelPageSize => {
                // The present-bit conjunct: a Windows transition
                // page-directory entry has bit 7 set as `Protection` bit 2,
                // and reading it as PS returned the PML4's own address as a
                // 2 MiB frame. A large page is locked and never in
                // transition, so nothing real is lost.
                if !(hardware_present && (entry & LARGE_PAGE_BIT) != 0) {
                    return Some(EntryKind::Table);
                }
                // Under PSE-36 a 4 MiB entry's bits 20:13 carry physical bits
                // 39:32 and bit 21 is reserved; a 32-bit physical width
                // cannot express such a frame, and masking those bits would
                // answer 4 GiB or more from the truth.
                if self.mode == PagingMode::Intel32
                    && mask_bits(entry, 21, PAGE_OFFSET_BITS + 1) != 0
                {
                    return Some(EntryKind::Unnameable {
                        detail: "a 4 MiB page-directory entry names a frame above \
                                 the 32-bit physical address space (PSE-36)",
                    });
                }
                // Bit 12 is the high PAT index on a large page and sits
                // inside the range a 4 KiB frame mask would read.
                (entry & !PAT_LARGE_BIT, (entry & NX_BIT) != 0)
            }
            LeafRule::IntelPage => (entry, (entry & NX_BIT) != 0),
            LeafRule::Arm64Block
            | LeafRule::Arm64TableOnly
            | LeafRule::Arm64TableOrLpaBlock
            | LeafRule::Arm64Page => {
                let Some(regime) = self.arm64() else {
                    return Some(EntryKind::Invalid);
                };
                let table_bit = (entry & ARM64_TABLE_BIT) != 0;
                let is_table = match page_level.leaf {
                    // A Windows transition entry has no valid bit and so no descriptor type:
                    // bit 1 is the low bit of `Protection`. Windows pages page tables and
                    // ordinary pages out, never a block, so above the last level it is a
                    // table and at it a page.
                    LeafRule::Arm64Page if !hardware_present => false,
                    _ if !hardware_present => true,
                    LeafRule::Arm64Page if !table_bit => return Some(EntryKind::Invalid),
                    LeafRule::Arm64Page => false,
                    LeafRule::Arm64TableOnly if !table_bit => return Some(EntryKind::Invalid),
                    // A block here exists only with FEAT_LPA/LPA2 on, and
                    // the image does not say whether it was. Reporting it
                    // absent would send an examiner past a region that may
                    // be mapped; reporting a frame would name one this build
                    // cannot vouch for. It is refused, with the reason.
                    LeafRule::Arm64TableOrLpaBlock if !table_bit => {
                        return Some(EntryKind::Unnameable {
                            detail: regime.granule.undecoded_lpa_block_detail(),
                        });
                    }
                    _ => table_bit,
                };
                // A table descriptor's next-level address and a leaf's output
                // address both gain bits 51:48 in these positions under
                // FEAT_LPA (64 KiB: bits 15:12) or FEAT_LPA2 (4 and 16 KiB:
                // bits 49:48). Whether the feature is on is `TCR_EL1.DS`,
                // which no image records, so a descriptor using them names an
                // address this reading cannot state — a table as much as a
                // page, since a masked table address reads somebody else's
                // table without a sign of it.
                let lpa_bits = match regime.granule {
                    Arm64Granule::Kb4 | Arm64Granule::Kb16 => ARM64_LPA2_OA_BITS,
                    Arm64Granule::Kb64 => ARM64_LPA_OA_BITS,
                };
                // Under `TCR_EL1.DS = 1` (a 16 KiB regime built from a recorded
                // register) they are address bits, decoded below, not a refusal.
                if !regime.lpa2 && (entry & lpa_bits) != 0 {
                    return Some(EntryKind::Unnameable {
                        detail: "the descriptor sets address bits that only exist under \
                                 FEAT_LPA or FEAT_LPA2 (a 52-bit physical space), which this \
                                 build does not decode; the address it names cannot be stated",
                    });
                }
                // An output address — a table's or a leaf's — above the
                // physical width `TCR_EL1.IPS` allows is an Address size
                // fault (D8.5): the hardware stops there, and masking the
                // bits away would answer with a different, real frame. A
                // regime whose IPS was never recorded uses the 48-bit
                // descriptor width, which this check cannot exceed.
                let above_ips = if regime.lpa2 {
                    // The whole output address, bits 51:50 from 9:8 included,
                    // read as the next table's or the frame's address.
                    let oa = arm64_lpa2_output_address(entry, regime.granule.page_shift());
                    regime.ips_bits < ARM64_MAX_OA_BITS_LPA2 && (oa >> regime.ips_bits) != 0
                } else {
                    regime.ips_bits < ARM64_MAX_OA_BITS
                        && mask_bits(
                            entry,
                            u32::from(ARM64_MAX_OA_BITS) - 1,
                            u32::from(regime.ips_bits),
                        ) != 0
                };
                if above_ips {
                    return Some(EntryKind::Unnameable {
                        detail: "Address size fault: the descriptor names an output address \
                                 above the physical width TCR_EL1.IPS allows; the hardware \
                                 stops here and no address is stated",
                    });
                }
                if is_table {
                    return Some(EntryKind::Table);
                }
                let xn = match regime.ttbr {
                    Ttbr::Ttbr0 => ARM64_UXN_BIT,
                    Ttbr::Ttbr1 => ARM64_PXN_BIT,
                };
                // A transition entry's bits 63:52 are reserved (`MMPTE_TRANSITION`), so the
                // execute-never bit is not read from one.
                (entry, hardware_present && (entry & xn) != 0)
            }
        };
        let frame = match self.arm64() {
            Some(regime) if regime.lpa2 => arm64_lpa2_output_address(frame_source, remaining),
            _ => mask_bits(frame_source, phys_high, remaining),
        };
        Some(EntryKind::Leaf {
            frame,
            size_log2: remaining,
            no_execute,
        })
    }

    /// The physical address of the table a non-leaf entry points at, from its
    /// own bits, for the table that `level + 1` of this spec indexes.
    ///
    /// The alignment mask is the child table's own size, and under an ARM64
    /// LPA2 regime address bits 51:50 come from descriptor bits 9:8 and bits
    /// 49:48 from the same bits of the descriptor.
    pub fn table_pa_of_entry(&self, entry: u64, level: usize) -> Option<u64> {
        let index_bits = self.levels().get(level)?.index_bits;
        let low = index_bits.checked_add(self.entry_size_log2())?;
        if self.arm64().is_some_and(|r| r.lpa2) {
            return Some(arm64_lpa2_output_address(entry, low));
        }
        let phys_high = self.max_phys_addr_bits.checked_sub(1)?;
        Some(mask_bits(entry, phys_high, low))
    }

    /// The physical address of the root table a recorded directory table base
    /// names, for the first level of this spec.
    ///
    /// Intel and ARM64 without LPA2 read it as any entry: the table's own
    /// alignment strips the control flags. An ARM64 LPA2 `TTBRn_EL1` is not laid
    /// out like a descriptor: `BADDR` is bits 47:1, with address bits 51:48 in
    /// bits 5:2, so reading it as one would take bits 9:8 of a 256-byte-aligned
    /// table's address for address bits 51:50.
    pub fn root_table_pa(&self, dtb: u64) -> Option<u64> {
        let top_bits = self.levels().first()?.index_bits;
        let low = top_bits.checked_add(self.entry_size_log2())?;
        if self.arm64().is_some_and(|r| r.lpa2) {
            let base = mask_bits(dtb, 47, low);
            let high = ((dtb >> 2) & 0xF) << 48;
            return Some(base | high);
        }
        let phys_high = self.max_phys_addr_bits.checked_sub(1)?;
        Some(mask_bits(dtb, phys_high, low))
    }

    /// Whether a **table** descriptor forces execute-never on everything
    /// below it, for this regime's own exception level.
    ///
    /// ARM64 (D8.4.2, hierarchical permission controls): `PXNTable`
    /// (bit 59) under TTBR1 and `UXNTable` (bit 60) under TTBR0 — the table
    /// counterparts of the leaf bit [`EntryKind::Leaf::no_execute`] reports —
    /// unless the regime records `TCR_EL1.HPDn = 1`, under which the
    /// hardware ignores them. Without FEAT_HPDS `HPDn` is RES0 and the bits
    /// always apply, which is why a regime built without a `TCR_EL1` folds
    /// them. Both walkers OR this into the leaf's own bit on the way down.
    ///
    /// `APTable` (bits 62:61) is not read: no access permission of any
    /// level is reported by this crate, so there is nothing to fold it into.
    ///
    /// Intel (SDM Vol. 3A 4.6): with `EFER.NXE = 1`, an instruction fetch is
    /// not allowed if XD (bit 63) is set in **any** paging-structure entry
    /// used to translate the address, so a non-leaf entry's XD is folded the
    /// same way — under the same caveat as the leaf's bit, that `NXE` is not
    /// recorded in an image. `level` matters on Intel alone: a PAE PDPTE
    /// (level 0) has no XD bit (bit 63 is reserved there), and 32-bit paging
    /// has none at any level.
    pub fn table_execute_never(&self, entry: u64, level: usize) -> bool {
        let Some(regime) = self.arm64() else {
            return match self.mode {
                PagingMode::Intel32 => false,
                PagingMode::IntelPae if level == 0 => false,
                _ => (entry & NX_BIT) != 0,
            };
        };
        if regime.hpd {
            return false;
        }
        let bit = match regime.ttbr {
            Ttbr::Ttbr0 => ARM64_UXN_TABLE_BIT,
            Ttbr::Ttbr1 => ARM64_PXN_TABLE_BIT,
        };
        (entry & bit) != 0
    }

    /// Whether the Windows 10 unused-address heuristic may be applied under
    /// this spec: Windows conventions on an Intel mode.
    ///
    /// The pattern — a page-sized table of identical present entries — was
    /// observed on x64 Windows 10. Nothing has been observed on ARM64
    /// Windows, so the heuristic does not fire there; an unobserved
    /// convention that hides tables is worse than none.
    pub fn uniform_table_heuristic_applies(&self) -> bool {
        self.semantics == PteSemantics::Windows && self.mode.is_intel()
    }

    /// The virtual address a walk that took `indices` at levels
    /// `0..indices.len()` and stopped there was translating, with `offset`
    /// inside the page it landed in.
    ///
    /// The exact inverse of [`index_source`](PagingSpec::index_source) and of
    /// the loop in [`PageWalk`](crate::translate::PageWalk). A walk taken
    /// upward is given an address and derives the indices; a walk taken
    /// **downward** has the indices and must name the address, and this is the
    /// only place that direction is computed.
    ///
    /// # The sign extension is reconstructed here
    ///
    /// The x64 tables index 48 bits and a kernel address is 64 bits of which
    /// the top sixteen — bits 63:48 — repeat bit 47.
    /// [`index_source`](PagingSpec::index_source) keeps bits 47:0, bit 47
    /// included, so a reconstruction that returned the indexed value would
    /// report every upper-half mapping exactly `0xFFFF_0000_0000_0000` too
    /// low — and every one of those wrong addresses is a perfectly ordinary
    /// user-space address, which is the class of error that does not look
    /// like one. In the 32-bit modes there is no extension and the indexed
    /// value is the address.
    ///
    /// `offset` is masked to the page these indices landed in, so a caller
    /// cannot carry a bit of the next page into the address.
    ///
    /// # Errors
    ///
    /// `None` when `indices` is empty, longer than this mode has levels, or an
    /// index does not fit the level it is for. Each of those is a caller's bug
    /// rather than a fact about an image, and masking the index instead would
    /// silently name a different address than the caller asked about.
    pub fn virtual_address_from_indices(&self, indices: &[u64], offset: u64) -> Option<u64> {
        if indices.is_empty() || indices.len() > self.levels().len() {
            return None;
        }
        let mut low = 0u64;
        let mut page_shift = self.max_virt_addr_bits;
        for (level, &index) in indices.iter().enumerate() {
            let bits = self.levels().get(level)?.index_bits;
            if bits >= 64 {
                return None;
            }
            if index >= (1u64 << bits) {
                return None;
            }
            let shift = self.index_shift(level)?;
            low |= index.checked_shl(shift)?;
            page_shift = shift;
        }
        if page_shift >= 64 {
            return None;
        }
        low |= offset & ((1u64 << page_shift) - 1);
        Some(self.sign_extend(low))
    }

    /// Put back the extension a canonical address carries above the bits the
    /// tables index.
    ///
    /// Takes the value [`index_source`](PagingSpec::index_source) would have
    /// returned and produces the address it came from. The result satisfies
    /// [`is_canonical`](PagingSpec::is_canonical) by construction, which is
    /// the property the round-trip test pins.
    fn sign_extend(&self, low: u64) -> u64 {
        if let Some(regime) = self.arm64() {
            // Not a sign: every address of a TTBR1 regime has the bits above
            // the width set, and every TTBR0 address has them clear.
            return match regime.ttbr {
                Ttbr::Ttbr0 => low,
                Ttbr::Ttbr1 => low | self.ttbr1_base(),
            };
        }
        if self.bits_per_register < 64 || self.max_virt_addr_bits >= 64 {
            return low;
        }
        let sign_bit = self.max_virt_addr_bits.saturating_sub(1);
        if sign_bit >= 64 {
            return low;
        }
        if (low >> sign_bit) & 1 == 1 {
            low | (u64::MAX << sign_bit)
        } else {
            low
        }
    }

    /// The top-level indices whose addresses sign-extend — the upper canonical
    /// half — or `None` for a mode that has no extension to describe.
    ///
    /// **Not** a claim about where the kernel is. That is an operating-system
    /// policy, and on 32-bit Windows the boundary is a boot option
    /// (`/3GB`). This is the architectural fact that an address whose top
    /// index falls in this range extends, which is the only thing a
    /// reconstruction needs and the only thing a report may assert from it.
    ///
    /// On ARM64 the extension is the regime's, not the index's: every
    /// top-level index of a TTBR1 spec extends and none of a TTBR0 spec does.
    pub fn upper_half_top_indices(&self) -> Option<std::ops::Range<u64>> {
        if self.bits_per_register < 64 || self.max_virt_addr_bits >= 64 {
            return None;
        }
        let bits = self.levels().first()?.index_bits;
        if bits == 0 || bits >= 64 {
            return None;
        }
        if let Some(regime) = self.arm64() {
            return match regime.ttbr {
                Ttbr::Ttbr0 => None,
                Ttbr::Ttbr1 => Some(0..(1u64 << bits)),
            };
        }
        Some((1u64 << (bits - 1))..(1u64 << bits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODES: [PagingMode; 4] = [
        PagingMode::Intel32,
        PagingMode::IntelPae,
        PagingMode::Intel32e,
        PagingMode::Intel32eLa57,
    ];

    #[test]
    fn an_address_rebuilt_from_its_own_indices_is_the_address_it_came_from() {
        // The property the whole downward enumeration rests on. A walk taken
        // upward decomposes an address into indices; a walk taken downward has
        // the indices and must name the address. If the two do not round-trip,
        // every mapping a downward enumeration reports is at a plausible wrong
        // address, which is the class of error that does not look like one.
        for mode in MODES {
            let spec = PagingSpec::new(mode, PteSemantics::Bare);
            let levels = spec.levels().len();
            let depth = levels - 1;
            for &va in &[0u64, 0x1000, 0x0040_1000, 0xFFFF_F000, 0x7FFF_FFFF_F000] {
                if !spec.is_canonical(va) || va > spec.max_virtual_address() {
                    continue;
                }
                let indices: Vec<u64> = (0..levels)
                    .map(|level| spec.index_at(va, level).expect("a level this mode has"))
                    .collect();
                assert_eq!(
                    spec.virtual_address_from_indices(&indices, va & 0xFFF),
                    Some(va),
                    "{mode} lost {va:#x} through its own indices at depth {depth}"
                );
            }
        }
    }

    #[test]
    fn a_kernel_address_rebuilt_from_its_indices_keeps_its_sign_extension() {
        // The x64 tables index 48 bits and a kernel address is 64 bits whose
        // top sixteen repeat bit 47. A reconstruction that returned the
        // indexed value would report every kernel mapping
        // 0xFFFF_8000_0000_0000 too low -- and every one of those addresses is
        // a perfectly ordinary user-space address.
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows);
        let va = 0xFFFF_F802_9FA0_0000u64;
        let indices: Vec<u64> = (0..spec.levels().len())
            .map(|level| spec.index_at(va, level).expect("a level this mode has"))
            .collect();
        assert_eq!(indices[0], 0x1F0, "PML4 index of a kernel address");
        assert_eq!(spec.virtual_address_from_indices(&indices, 0), Some(va));

        let la57 = PagingSpec::new(PagingMode::Intel32eLa57, PteSemantics::Windows);
        let va = 0xFF00_0000_0040_1000u64;
        let indices: Vec<u64> = (0..la57.levels().len())
            .map(|level| la57.index_at(va, level).expect("a level this mode has"))
            .collect();
        assert_eq!(
            indices[0], 0x100,
            "PML5 index of the lowest LA57 kernel address"
        );
        assert_eq!(la57.virtual_address_from_indices(&indices, 0), Some(va));
    }

    #[test]
    fn a_large_page_is_rebuilt_from_the_indices_it_actually_had() {
        // A 1 GiB or 2 MiB page ends the walk early, so there are fewer
        // indices than the mode has levels and the page offset is wider. Both
        // have to come from the same place or a large page is named at the
        // address of its first 4 KiB.
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        // PML4 0, PDPT 1 -> a 1 GiB page at 0x4000_0000, and a byte 0x1234
        // into it.
        assert_eq!(
            spec.virtual_address_from_indices(&[0, 1], 0x1234),
            Some(0x4000_1234)
        );
        // PML4 0, PDPT 0, PD 3 -> a 2 MiB page at 0x60_0000.
        assert_eq!(
            spec.virtual_address_from_indices(&[0, 0, 3], 0),
            Some(0x60_0000)
        );
        // 32-bit non-PAE: one index is a 4 MiB page.
        let intel32 = PagingSpec::new(PagingMode::Intel32, PteSemantics::Bare);
        assert_eq!(
            intel32.virtual_address_from_indices(&[2], 0x10),
            Some(0x0080_0010)
        );
    }

    #[test]
    fn a_page_offset_wider_than_the_page_cannot_reach_the_next_page() {
        // The offset is masked to the page the indices landed in. Carrying a
        // bit of the next page into the address would name a page that is
        // mapped somewhere else entirely.
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        assert_eq!(
            spec.virtual_address_from_indices(&[0, 0, 0, 1], 0x1FFF),
            Some(0x1FFF),
            "a 4 KiB page keeps only twelve bits of offset"
        );
    }

    #[test]
    fn indices_that_do_not_belong_to_this_mode_name_no_address() {
        // Each of these is a caller's mistake rather than a fact about an
        // image, and masking the index instead would silently name a
        // different address than the caller asked for.
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        assert_eq!(
            spec.virtual_address_from_indices(&[], 0),
            None,
            "no indices"
        );
        assert_eq!(
            spec.virtual_address_from_indices(&[0, 0, 0, 0, 0], 0),
            None,
            "more indices than the mode has levels"
        );
        assert_eq!(
            spec.virtual_address_from_indices(&[512, 0, 0, 0], 0),
            None,
            "an index wider than the nine bits that level takes"
        );
        let pae = PagingSpec::new(PagingMode::IntelPae, PteSemantics::Bare);
        assert_eq!(
            pae.virtual_address_from_indices(&[4, 0, 0], 0),
            None,
            "the PAE pointer table has four entries, not five"
        );
    }

    #[test]
    fn the_bits_a_level_governs_are_its_page_size_where_a_page_can_end_there() {
        // The same number as log2(Translation::run_len), which is how a
        // downward walk reports a run length without deriving one of its own.
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        assert_eq!(spec.region_bits_at(1), Some(30), "a 1 GiB page");
        assert_eq!(spec.region_bits_at(2), Some(21), "a 2 MiB page");
        assert_eq!(spec.region_bits_at(3), Some(12), "a 4 KiB page");
        assert_eq!(spec.region_bits_at(4), None, "a level this mode has not");
        let intel32 = PagingSpec::new(PagingMode::Intel32, PteSemantics::Bare);
        assert_eq!(intel32.region_bits_at(0), Some(22), "a 4 MiB page");
        assert_eq!(intel32.region_bits_at(1), Some(12));
    }

    #[test]
    fn a_level_no_page_can_end_at_still_states_the_region_its_entry_governs() {
        // 39 bits at an Intel32e PML4 entry is not a page size -- Intel
        // defines no 512 GiB page -- it is the span a *not present* entry
        // there declares absent, which is the number a caller
        // recording that hole needs. So the width is published and
        // `terminates_at` is what says whether it may be read as a page.
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        assert_eq!(spec.region_bits_at(0), Some(39), "a 512 GiB PML4 region");
        assert_eq!(
            spec.terminates_at(0),
            Some(false),
            "Intel has no 512 GiB page"
        );
        assert_eq!(spec.terminates_at(1), Some(true), "a 1 GiB page");
        assert_eq!(spec.terminates_at(2), Some(true), "a 2 MiB page");
        assert_eq!(spec.terminates_at(3), Some(true), "the final level always");
        assert_eq!(spec.terminates_at(4), None, "a level this mode has not");

        // PAE's pointer level has no page size of its own either, and its
        // region is 1 GiB.
        let pae = PagingSpec::new(PagingMode::IntelPae, PteSemantics::Bare);
        assert_eq!(pae.region_bits_at(0), Some(30));
        assert_eq!(pae.terminates_at(0), Some(false));
        assert_eq!(pae.terminates_at(1), Some(true), "a 2 MiB page");

        // And the two agree with the level table itself, in every mode, so
        // neither can drift from the declaration the walk reads.
        for mode in MODES {
            let spec = PagingSpec::new(mode, PteSemantics::Bare);
            let last = spec.levels().len() - 1;
            for (level, page_level) in spec.levels().iter().enumerate() {
                assert_eq!(
                    spec.terminates_at(level),
                    Some(page_level.leaf == LeafRule::IntelPageSize || level == last),
                    "{mode} level {level} disagrees with its own declaration"
                );
            }
        }
    }

    #[test]
    fn a_top_level_index_in_the_upper_half_is_the_one_whose_addresses_extend() {
        // An architectural fact, not a claim about where an operating system
        // put its kernel: on 32-bit Windows that boundary is a boot option.
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        assert_eq!(spec.upper_half_top_indices(), Some(256..512));
        let la57 = PagingSpec::new(PagingMode::Intel32eLa57, PteSemantics::Bare);
        assert_eq!(la57.upper_half_top_indices(), Some(256..512));
        for mode in [PagingMode::Intel32, PagingMode::IntelPae] {
            assert_eq!(
                PagingSpec::new(mode, PteSemantics::Bare).upper_half_top_indices(),
                None,
                "{mode} has no sign extension to describe"
            );
        }
        // And it agrees with is_canonical, which is the only thing that makes
        // it useful: every address built from a top index in the range
        // extends, and none built from an index below it does.
        let indices = [255u64, 256];
        for index in indices {
            let va = spec
                .virtual_address_from_indices(&[index, 0, 0, 0], 0)
                .expect("a valid index");
            let extends = spec
                .upper_half_top_indices()
                .is_some_and(|r| r.contains(&index));
            assert_eq!(
                va >> 63 == 1,
                extends,
                "index {index} extended the wrong way"
            );
            assert!(spec.is_canonical(va), "{va:#x} is not canonical");
        }
    }

    #[test]
    fn mask_bits_is_inclusive_at_both_ends() {
        // Bits 3:1 of 0b1111_1111 are 0b0000_1110, kept in place.
        assert_eq!(mask_bits(0xFF, 3, 1), 0b1110);
        // The high end really is included: bit 51 of a 52-bit physical address
        // survives a mask of (51, 12).
        assert_eq!(mask_bits(1 << 51, 51, 12), 1 << 51);
        // And the low end really is included: bit 12 survives.
        assert_eq!(mask_bits(1 << 12, 51, 12), 1 << 12);
        assert_eq!(mask_bits(1 << 11, 51, 12), 0);
    }

    #[test]
    fn mask_bits_handles_the_top_of_the_word_without_overflowing() {
        assert_eq!(mask_bits(u64::MAX, 63, 0), u64::MAX);
        assert_eq!(mask_bits(u64::MAX, 63, 63), 1 << 63);
    }

    #[test]
    fn a_nonsensical_mask_range_yields_nothing_rather_than_panicking() {
        assert_eq!(mask_bits(u64::MAX, 3, 9), 0);
        assert_eq!(mask_bits(u64::MAX, 70, 64), 0);
    }

    #[test]
    fn every_mode_indexes_exactly_its_virtual_address_width() {
        // If a level table and the declared virtual width ever disagree, every
        // index in that mode is shifted by the difference and every
        // translation is wrong but plausible.
        for mode in MODES {
            let spec = PagingSpec::new(mode, PteSemantics::Bare);
            let indexed: u32 = spec.levels().iter().map(|l| l.index_bits).sum();
            assert_eq!(
                indexed + PAGE_OFFSET_BITS,
                spec.max_virt_addr_bits(),
                "{mode} level table does not cover its virtual address width"
            );
        }
    }

    #[test]
    fn no_mode_treats_its_final_level_as_a_large_page_level() {
        // Bit 7 of a 4 KiB PTE is the PAT index. A level table that marked the
        // final level as large-page-capable would turn ordinary
        // write-combining pages into 4 MiB / 2 MiB frames.
        for mode in MODES {
            let spec = PagingSpec::new(mode, PteSemantics::Bare);
            let last = spec.levels().len() - 1;
            assert_eq!(
                spec.levels()[last].leaf,
                LeafRule::IntelPage,
                "{mode} final level"
            );
            assert!(
                spec.levels()[0].leaf != LeafRule::IntelPageSize || mode == PagingMode::Intel32
            );
        }
    }

    #[test]
    fn maxphyaddr_is_a_per_cell_parameter_not_an_os_property() {
        // Windows narrows x64 only. If this ever becomes a mixin, 32-bit and
        // PAE masks widen past the architectural width.
        assert_eq!(
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows).max_phys_addr_bits(),
            45
        );
        assert_eq!(
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare).max_phys_addr_bits(),
            52
        );
        assert_eq!(
            PagingSpec::new(PagingMode::IntelPae, PteSemantics::Windows).max_phys_addr_bits(),
            40
        );
        assert_eq!(
            PagingSpec::new(PagingMode::Intel32, PteSemantics::Windows).max_phys_addr_bits(),
            32
        );
    }

    #[test]
    fn the_swap_bit_offset_follows_the_entry_width_not_the_paging_mode_family() {
        assert_eq!(
            PagingSpec::new(PagingMode::Intel32, PteSemantics::Windows).swap_bit_offset(),
            12
        );
        assert_eq!(
            PagingSpec::new(PagingMode::IntelPae, PteSemantics::Windows).swap_bit_offset(),
            32
        );
        assert_eq!(
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows).swap_bit_offset(),
            32
        );
    }

    #[test]
    fn x64_rejects_a_non_canonical_address_and_accepts_both_halves() {
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        assert!(spec.is_canonical(0));
        assert!(spec.is_canonical(0x0000_7FFF_FFFF_FFFF));
        assert!(spec.is_canonical(0xFFFF_8000_0000_0000));
        assert!(spec.is_canonical(u64::MAX));
        // The unusable middle: one past the top of the lower half, and one
        // below the bottom of the upper half.
        assert!(!spec.is_canonical(0x0000_8000_0000_0000));
        assert!(!spec.is_canonical(0xFFFF_7FFF_FFFF_FFFF));
        assert!(!spec.is_canonical(0x1234_5678_9ABC_DEF0));
    }

    #[test]
    fn thirty_two_bit_modes_truncate_rather_than_sign_extend() {
        for mode in [PagingMode::Intel32, PagingMode::IntelPae] {
            let spec = PagingSpec::new(mode, PteSemantics::Bare);
            assert!(spec.is_canonical(0xFFFF_FFFF), "{mode} top of the space");
            assert!(!spec.is_canonical(0x1_0000_0000), "{mode} past the space");
            assert_eq!(spec.max_virtual_address(), 0xFFFF_FFFF);
        }
        assert_eq!(
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare).max_virtual_address(),
            u64::MAX
        );
    }

    #[test]
    fn the_index_source_strips_a_canonical_sign_extension() {
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        // Kernel space: PML4 index 256 is the first index of the upper half.
        let va = 0xFFFF_8000_0040_1000;
        assert_eq!(spec.index_source(va), 0x0000_8000_0040_1000);
        assert_eq!((spec.index_source(va) >> 39) & 0x1FF, 256);
    }

    #[test]
    fn a_transition_entry_is_usable_under_windows_and_not_under_bare() {
        let entry = WINDOWS_TRANSITION_BIT | 0x5000;
        let win = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows);
        let bare = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        assert!(win.entry_is_present(entry));
        assert!(!bare.entry_is_present(entry));
        // Transition AND prototype together is not a usable frame.
        assert!(!win.entry_is_present(entry | WINDOWS_PROTOTYPE_BIT));
    }

    #[test]
    fn a_windows_software_pte_decodes_to_a_pagefile_location() {
        // Pre-Windows-8 layout: PageFileLow at bits 4:1.
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows)
            .with_win8_pagefile_layout(false);
        let entry = (3u64 << 1) | (0x1234u64 << 32);
        assert!(!spec.entry_is_present(entry));
        assert_eq!(
            spec.classify_invalid(entry),
            InvalidEntry::PageFile {
                index: Some(3),
                page_number: 0x1234,
            }
        );

        // The same bits on a Windows 8+ image name a different pagefile,
        // because the field moved to 15:12. Reading 4:1 there would report
        // pagefile 3 with total confidence and be wrong.
        let win8 = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows)
            .with_win8_pagefile_layout(true);
        let win8_entry = (3u64 << 12) | (0x1234u64 << 32);
        assert_eq!(
            win8.classify_invalid(win8_entry),
            InvalidEntry::PageFile {
                index: Some(3),
                page_number: 0x1234,
            }
        );

        // A spec never told which build it is reports the offset — which does
        // not move — and declines to name a pagefile.
        let unknown = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows);
        assert_eq!(
            unknown.classify_invalid(entry),
            InvalidEntry::PageFile {
                index: None,
                page_number: 0x1234,
            },
            "an unknown build must not guess which pagefile"
        );
    }

    #[test]
    fn an_unknown_build_does_not_name_a_pagefile() {
        // The failure this replaces: the index was read from bits 4:1
        // unconditionally. On a Windows 8-or-later image those bits hold
        // PageFileReserved, PageFileAllocated, ColdPage and SwizzleBit, so the
        // decode returned a small plausible integer that named the wrong
        // pagefile — with no indication anything was assumed. An examiner sent
        // to the wrong pagefile has been sent there confidently.
        let unknown = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows);
        assert_eq!(unknown.swap_index_shift(), None);

        // Same bits, three readings: the offset is identical in all of them
        // because PageFileHigh did not move. Only the index differs, which is
        // exactly why it is the part that must not be guessed.
        let entry = (3u64 << 1) | (5u64 << 12) | (0x1234u64 << 32);
        let pre = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows)
            .with_win8_pagefile_layout(false);
        let post = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows)
            .with_win8_pagefile_layout(true);

        let index_of = |spec: &PagingSpec| match spec.classify_invalid(entry) {
            InvalidEntry::PageFile { index, page_number } => {
                assert_eq!(page_number, 0x1234, "the offset never moves");
                index
            }
            other => panic!("expected a pagefile entry, got {other:?}"),
        };

        assert_eq!(index_of(&pre), Some(3));
        assert_eq!(index_of(&post), Some(5));
        assert_eq!(
            index_of(&unknown),
            None,
            "with no build, neither reading may be presented as the answer"
        );
    }

    #[test]
    fn a_prototype_pte_is_never_reported_as_a_pagefile_location() {
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows);
        let entry = WINDOWS_PROTOTYPE_BIT | (0x1234u64 << 32);
        assert_eq!(spec.classify_invalid(entry), InvalidEntry::Prototype);
    }

    #[test]
    fn an_x64_prototype_address_is_recovered_with_its_sign_extension() {
        // The field is a SIGNED 48-bit value at bits 63:16 holding the whole
        // kernel virtual address. A logical shift instead of an arithmetic one
        // drops the sign extension and yields a lower-half address — which
        // translates, reads somebody else's page, and looks entirely ordinary.
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows);
        for va in [
            0xFFFF_8000_0000_0008u64,
            0xFFFF_FFFF_8AB0_1230,
            0x0000_0000_0040_1000,
        ] {
            let entry =
                (((va as i64) << WINDOWS_X64_PROTO_ADDRESS_SHIFT) as u64) | WINDOWS_PROTOTYPE_BIT;
            assert_eq!(
                spec.prototype_address(entry),
                Some(va),
                "{va:#x} must round-trip through the ProtoAddress field"
            );
        }
    }

    #[test]
    fn a_prototype_address_that_cannot_be_stated_is_not_invented() {
        let x64 = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows);
        // MI_PTE_LOOKUP_NEEDED: the address is not in the entry at all and
        // Windows recomputes it from the VAD's subsection chain.
        assert_eq!(x64.prototype_address(u64::MAX), None);
        // A zero field names no array.
        assert_eq!(x64.prototype_address(WINDOWS_PROTOTYPE_BIT), None);
        // Whatever the field holds, the decoded address is canonical by
        // construction, so a walk can never be sent to an address the machine
        // could not have issued.
        for entry in [1u64, 0x1234_5678, u64::MAX / 2, u64::MAX - 1] {
            if let Some(va) = x64.prototype_address(entry) {
                assert!(x64.is_canonical(va), "{entry:#x} -> {va:#x}");
            }
        }

        // 32-bit non-PAE splits ProtoAddress across two fields whose widths
        // moved between builds. Decoding it would be guessing.
        let x86 = PagingSpec::new(PagingMode::Intel32, PteSemantics::Windows);
        assert_eq!(x86.prototype_address(0xFFFF_FFFF), None);

        // And a bare walker has no prototype PTEs to decode.
        let bare = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        assert_eq!(
            bare.prototype_address(((0xFFFF_8000_0000_0008u64 as i64) << 16) as u64),
            None
        );
    }

    #[test]
    fn a_pae_prototype_address_is_the_upper_thirty_two_bits() {
        let pae = PagingSpec::new(PagingMode::IntelPae, PteSemantics::Windows);
        let entry = (0x8AB0_1230u64 << WINDOWS_PAE_PROTO_ADDRESS_SHIFT) | WINDOWS_PROTOTYPE_BIT;
        assert_eq!(pae.prototype_address(entry), Some(0x8AB0_1230));
        assert_eq!(
            pae.prototype_address(0xFFFF_FFFFu64 << WINDOWS_PAE_PROTO_ADDRESS_SHIFT),
            None,
            "MI_PTE_LOOKUP_NEEDED is 32 bits wide here"
        );
    }

    #[test]
    fn an_empty_non_present_entry_claims_nothing() {
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows);
        assert_eq!(spec.classify_invalid(0), InvalidEntry::NotPresent);
        // A software PTE with no PageFileHigh names no location on disk, so
        // reporting a swap offset of zero would be an invention.
        assert_eq!(spec.classify_invalid(3 << 1), InvalidEntry::NotPresent);
    }

    #[test]
    fn bare_semantics_never_claim_a_page_is_swapped() {
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        let windows_looking = (3u64 << 1) | (0x1234u64 << 32);
        assert_eq!(
            spec.classify_invalid(windows_looking),
            InvalidEntry::NotPresent
        );
    }

    #[test]
    fn identifiers_are_stable_for_artifact_metadata() {
        assert_eq!(PagingMode::Intel32e.as_str(), "intel32e");
        assert_eq!(PagingMode::IntelPae.to_string(), "intel_pae");
        assert_eq!(PagingMode::Intel32eLa57.as_str(), "intel32e_la57");
        assert_eq!(PteSemantics::Windows.as_str(), "windows");
        assert_eq!(PteSemantics::Bare.to_string(), "bare");
        assert_eq!(PteSemantics::Linux.to_string(), "linux");
        // Two modes that walk different numbers of levels must never share a
        // name: the name is what a report and a re-run are matched on, and an
        // LA57 case labelled `intel32e` would be re-opened four levels deep.
        assert_ne!(
            PagingMode::Intel32e.as_str(),
            PagingMode::Intel32eLa57.as_str()
        );
    }

    #[test]
    fn la57_translates_five_levels_of_a_fifty_seven_bit_space() {
        // The defect: `PagingMode` had no five-level member at all, so an LA57
        // capture had no mode to be declared under. `PagingSpec::new` would not
        // have compiled with this argument before the variant existed, and the
        // numbers below are the ones the walker is parameterised on — a table
        // that indexed 48 bits under a 57-bit declaration would shift every
        // index in the mode.
        let spec = PagingSpec::new(PagingMode::Intel32eLa57, PteSemantics::Linux);
        assert_eq!(spec.max_virt_addr_bits(), 57);
        assert_eq!(spec.levels().len(), 5);
        assert_eq!(spec.level_name(0), Some("page map level 5"));
        assert_eq!(spec.level_name(4), Some("page table"));
        assert_eq!(spec.level_name(5), None);
        // The entry format is unchanged from four-level x64: same width, same
        // physical ceiling, same software-PTE offset.
        assert_eq!(spec.entry_size(), 8);
        assert_eq!(spec.max_phys_addr_bits(), 52);
        assert_eq!(spec.swap_bit_offset(), 32);
        assert_eq!(
            PagingSpec::new(PagingMode::Intel32eLa57, PteSemantics::Windows).max_phys_addr_bits(),
            45,
            "Windows' x64 software bits are a property of the entry, which LA57 does not change"
        );
    }

    #[test]
    fn la57_canonicality_is_measured_from_bit_fifty_six_not_bit_forty_seven() {
        // The half of the defect that produced wrong answers rather than
        // missing ones: under four-level rules every 57-bit-canonical kernel
        // address is refused as non-canonical, so a whole class of real
        // addresses had no translation at all.
        let la57 = PagingSpec::new(PagingMode::Intel32eLa57, PteSemantics::Linux);
        let four = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Linux);

        // The first address of the LA57 upper canonical half. Four-level rules
        // reject it; five-level rules must not.
        assert!(la57.is_canonical(0xFF00_0000_0000_0000));
        assert!(!four.is_canonical(0xFF00_0000_0000_0000));
        // An address that is canonical under both, because the sign extension
        // runs all the way up.
        assert!(la57.is_canonical(0xFFFF_FFFF_8000_0000));
        assert!(four.is_canonical(0xFFFF_FFFF_8000_0000));
        // LA57's own unusable middle still has to be refused, or a corrupt
        // pointer becomes a confident translation.
        assert!(!la57.is_canonical(0x0100_0000_0000_0000));
        assert!(!la57.is_canonical(0xFEFF_FFFF_FFFF_FFFF));
        assert!(la57.is_canonical(0x00FF_FFFF_FFFF_FFFF));
        assert_eq!(la57.max_virtual_address(), u64::MAX);

        // And the index source keeps 57 bits, so the top table is indexed by
        // bits 56:48. For a kernel text address those are all ones.
        let va = 0xFFFF_FFFF_8000_0000u64;
        assert_eq!(la57.index_source(va), va & ((1u64 << 57) - 1));
        assert_eq!((la57.index_source(va) >> 48) & 0x1FF, 0x1FF);
    }

    #[test]
    fn linux_separates_an_empty_entry_from_a_page_the_kernel_moved_out() {
        // The defect: under `Bare` every non-present Linux entry classified as
        // `NotPresent`, so a page that was never mapped and a page the kernel
        // swapped out were the same answer. `InvalidEntry::LinuxSwapEntry` did
        // not exist to distinguish them.
        let linux = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Linux);

        // `pte_none()`: empty, including with the accessed/dirty bits a
        // processor may have set spuriously on a non-present entry.
        assert_eq!(linux.classify_invalid(0), InvalidEntry::NotPresent);
        assert_eq!(linux.classify_invalid(1 << 5), InvalidEntry::NotPresent);
        assert_eq!(linux.classify_invalid(1 << 6), InvalidEntry::NotPresent);
        assert_eq!(
            linux.classify_invalid(LINUX_EMPTY_ENTRY_IGNORED_BITS),
            InvalidEntry::NotPresent
        );

        // `_PAGE_PROTNONE`: the kernel calls this present and holds a frame for
        // it. Nothing was written to swap, so it must not be reported as a page
        // whose contents moved.
        assert_eq!(
            linux.classify_invalid(LINUX_PROTNONE_BIT | (0x1234u64 << 12)),
            InvalidEntry::NotPresent
        );
        assert!(!linux.entry_is_present(LINUX_PROTNONE_BIT | (0x1234u64 << 12)));

        // Anything else non-present is a `swp_entry_t`. All three historical
        // x86-64 layouts land here, which is the point: the classification does
        // not depend on which one built the image.
        for entry in [
            // Linux 3.x: type at bits 5:1, offset above bit 9.
            (2u64 << 1) | (0x9ABCu64 << 9),
            // Linux 4.x before the L1TF mitigation: type at 13:9, offset above
            // bit 14.
            (2u64 << 9) | (0x9ABCu64 << 14),
            // Since the L1TF mitigation: type at 63:59, inverted offset below.
            (2u64 << 59) | (((!0x9ABCu64) << 14) >> 5),
        ] {
            assert_eq!(
                linux.classify_invalid(entry),
                InvalidEntry::LinuxSwapEntry,
                "{entry:#x} is a swap-family entry under every x86-64 layout"
            );
            assert!(!linux.entry_is_present(entry));
        }

        // Bare still says nothing about any of them, so an image whose OS was
        // never established does not acquire a Linux reading.
        let bare = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        assert_eq!(
            bare.classify_invalid((2u64 << 9) | (0x9ABCu64 << 14)),
            InvalidEntry::NotPresent
        );
    }

    #[test]
    fn linux_semantics_name_no_swap_area_and_no_offset() {
        // The refusal, asserted as a shape rather than as prose. The area and
        // the page within it are in the entry; the bit positions that read them
        // moved three times on x86-64 and the L1TF change was backported below
        // 4.19, so the kernel's own version string cannot select between the
        // layouts. A decode against the wrong one returns another page's
        // contents rather than failing, so no number is produced at all.
        //
        // `InvalidEntry::LinuxSwapEntry` is field-less, and this is what keeps
        // it that way: adding a field would require a caller to fill it.
        let linux = PagingSpec::new(PagingMode::Intel32eLa57, PteSemantics::Linux);
        let swapped = (2u64 << 9) | (0x9ABCu64 << 14);
        assert_eq!(
            linux.classify_invalid(swapped),
            InvalidEntry::LinuxSwapEntry
        );
        // The Windows software-PTE reading of the same bits is not reachable
        // from Linux semantics: it would name pagefile 2 at a plausible offset.
        assert!(!matches!(
            linux.classify_invalid(swapped),
            InvalidEntry::PageFile { .. }
        ));
        // Nor does a prototype address exist to be decoded outside Windows.
        assert_eq!(linux.prototype_address(swapped), None);
    }

    #[test]
    fn level_names_are_reachable_for_error_messages() {
        let spec = PagingSpec::new(PagingMode::Intel32e, PteSemantics::Bare);
        assert_eq!(spec.level_name(0), Some("page map level 4"));
        assert_eq!(spec.level_name(3), Some("page table"));
        assert_eq!(spec.level_name(4), None);
    }
}
