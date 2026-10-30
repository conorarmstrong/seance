//! Windows XP and Server 2003 network endpoints, from the two objects their
//! tcpip.sys actually allocates.
//!
//! [`super::netscan`] sweeps for `TcpE`, `TcpL` and `UdpA`. Nothing before
//! Windows Vista allocates under those tags, because nothing before Vista has
//! the objects they mark: the rewritten TCP/IP stack that introduced
//! `_TCP_ENDPOINT`, `_TCP_LISTENER`, `_UDP_ENDPOINT`, `_INETAF` and the
//! partition table shipped in Vista. Before that, tcpip.sys keeps
//!
//! * one **`_ADDRESS_OBJECT`** per bound endpoint, under the pool tag `TCPA`.
//!   It is what a listening TCP service, a bound UDP socket and a raw socket all
//!   are on XP, told apart by an IANA protocol number in the object rather than
//!   by the tag; and
//! * one **`_TCPT_OBJECT`** per TCP connection, under the pool tag `TCPT`. It is
//!   the TCP control block, carrying both addresses and both ports inline.
//!
//! Sweeping for those two tags is what makes an XP image yield a network at all.
//!
//! # Why the layouts are declared here and not read from a symbol table
//!
//! They cannot be read from one. `_ADDRESS_OBJECT` and `_TCPT_OBJECT` are
//! internal to tcpip.sys, and the PDBs Microsoft published for XP's tcpip.sys
//! are *public* PDBs: they carry function and global symbols and **no type
//! records at all**. There is no ISF anywhere that describes these two
//! structures, and there never will be one derived from Microsoft's symbols. So
//! the layout is stated here, as an ISF compiled through exactly the same
//! [`SymbolTable`] machinery every other stage reads through — which means the
//! offsets are in one auditable place, are proved to exist before anything is
//! read, and are subject to the same admission gates as a vendor table.
//!
//! # Why one build family and not "pre-Vista"
//!
//! A stated layout is only worth as much as the evidence it was checked
//! against. The layout in [`XP_X86_ISF`] was confirmed member by member against
//! a real Windows XP SP2 x86 image: every `PID` fell on a process the image's
//! own process list holds, every `CreateTime` fell inside the machine's uptime,
//! and the ports and addresses reconstruct a coherent machine — `snmp.exe` on
//! UDP 161, `tcpsvcs.exe` on the simple TCP/IP services, `lsass.exe` on the
//! IPsec IKE ports, `System` on the NetBIOS and SMB ports.
//!
//! Server 2003 moved these members, and no Server 2003 image was available to
//! confirm where to. So [`LEGACY_LAYOUTS`] is keyed on the exact build family
//! each entry was confirmed against, a family with no entry is refused by name,
//! and there is no "closest match" arm. Decoding 2003 at XP's offsets would not
//! fail: it would produce a table of plausible addresses, plausible ports and
//! plausible PIDs, which is the one outcome this crate exists to prevent.
//!
//! # Windows XP's pool header means the opposite of Vista's
//!
//! `_POOL_HEADER.PoolType` on XP holds `POOL_TYPE + 1`, so a **non-paged**
//! allocation is **odd** — `NonPagedPool` (0) stores 1, `NonPagedPoolCacheAligned`
//! (4) stores 5, which is what tcpip.sys's endpoints are — a **paged** one is
//! even and non-zero, and a **freed** one is zero. The modern sweep's own
//! candidate check applies the Vista rule, where non-paged is even. Running an XP
//! sweep through it would
//! reject every live endpoint on the machine and keep only the freed ones, which
//! reads as a machine that had closed all its connections. The rule is therefore
//! applied here, in the direction this build encodes it, and
//! [`legacy_pool_state`] is the only place either direction is decided.
//!
//! # IPv4 only, and why that is a statement rather than a limitation
//!
//! XP's IPv6 stack is a separate driver, `tcpip6.sys`, with its own objects.
//! Nothing reachable through `TCPA` or `TCPT` is an IPv6 endpoint, so there is
//! no address family to read and no family member in either structure. A row
//! from this stage is IPv4 because the object it came from could not have been
//! anything else — not because a family was assumed.

use std::ops::Range;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::{Obj, PlausibilityFailure};
use seance_memory::scan::{scan_layer, scan_range, MultiStringScanner};
use seance_memory::Incomplete;
use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

use crate::profile::{KernelBuild, WindowsProfile};

use super::decode::{
    format_ipv4, plausible_owner, read_create_time, read_port, IPPROTO_TCP, IPPROTO_UDP,
};
use super::{
    push_rejection, NetError, NetscanConfig, NetscanOutcome, NetworkEndpoint, ObjectKind, PoolTag,
    Protocol, Readers, Rejected, ScanSpace, SocketState, POOL_TAG_MEMBER, TYPE_ADDRESS_OBJECT,
    TYPE_POOL_HEADER, TYPE_TCPT_OBJECT,
};

/// The pool tag XP's tcpip.sys allocates every `_ADDRESS_OBJECT` under.
pub const TAG_ADDRESS_OBJECT: &str = "TCPA";

/// The pool tag XP's tcpip.sys allocates every `_TCPT_OBJECT` under.
pub const TAG_TCPT_OBJECT: &str = "TCPT";

/// Highest value an IANA IP protocol number can take.
///
/// `_ADDRESS_OBJECT.Protocol` is a two-byte member holding a one-byte quantity,
/// so anything above this is not a protocol number: it is four bytes of
/// something else under a tag that happened to match.
pub const MAX_IP_PROTOCOL: u16 = 255;

/// One legacy layout, and the exact build family it was confirmed against.
///
/// The family is part of the record rather than a comment, because the whole
/// safety of this stage is that a build outside it is refused rather than
/// decoded at the nearest neighbour's offsets.
#[derive(Debug, Clone, Copy)]
pub struct LegacyLayout {
    /// `NtMajorVersion` this layout was confirmed on.
    pub major: u32,
    /// `NtMinorVersion` this layout was confirmed on.
    pub minor: u32,
    /// Guest pointer width in bytes this layout was confirmed on.
    pub pointer_size: u64,
    /// How a report names the family.
    pub family: &'static str,
    /// The image the offsets were read out of and checked against.
    pub confirmed_against: &'static str,
    /// The ISF declaring the two structures.
    pub isf: &'static str,
}

/// Every legacy layout this stage has evidence for.
///
/// One entry. Adding a second means confirming it against an image of that
/// family the same way; there is deliberately no fallback arm, so an
/// unrepresented family is refused by name instead of reaching a decoder.
pub const LEGACY_LAYOUTS: &[LegacyLayout] = &[LegacyLayout {
    major: 5,
    minor: 1,
    pointer_size: 4,
    family: "Windows XP (NT 5.1), 32-bit",
    confirmed_against: "a Windows XP SP2 x86 image (NTBuildLab 2600.xpsp_sp2_gdr.050301-1519)",
    isf: XP_X86_ISF,
}];

/// The two tcpip.sys structures Windows XP x86 tracks endpoints in.
///
/// # Where each offset comes from
///
/// Every one was read out of a real XP SP2 x86 image and cross-checked against
/// something the image states independently:
///
/// * `_ADDRESS_OBJECT.Pid` (0x148) and `.CreateTime` (0x158) were located by
///   scanning each candidate for a value matching the image's own process list
///   and for a FILETIME inside the machine's uptime. Both landed on one offset
///   across every candidate, and on no other.
/// * `_ADDRESS_OBJECT.LocalIpAddress` (0x2c), `.LocalPort` (0x30) and
///   `.Protocol` (0x32) reconstruct a coherent machine at those offsets:
///   `snmp.exe` on UDP 161, `tcpsvcs.exe` on TCP and UDP 7, 9, 13, 17 and 19,
///   `lsass.exe` on UDP 500 and 4500, `System` on 137, 138, 139 and 445.
/// * `_TCPT_OBJECT.LocalIpAddress` (0x10) and `.LocalPort` (0x16) agree with the
///   `_ADDRESS_OBJECT`s the same processes hold: `iexplore.exe`'s connections
///   have local ports 1066 and 1077, and `iexplore.exe` owns address objects
///   bound to exactly those. That is what distinguishes local from remote here,
///   and reading the pair the other way round would report this laptop as a web
///   server.
///
/// # The declared sizes
///
/// 360 and 400 bytes: the pool allocations these objects arrive in are 368 and
/// 408 bytes on this build, less the eight-byte `_POOL_HEADER`. Stating the real
/// size rather than the read extent means the containment check below refuses an
/// allocation too small to be one of these objects, instead of
/// reading five members out of the first thirty bytes of something else.
pub const XP_X86_ISF: &str = r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "00000000000000000000000000000000", "age": 0,
                        "database": "tcpip.pdb", "machine_type": 332}}
  },
  "base_types": {
    "pointer": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "unsigned long long": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "unsigned short": {"size": 2, "signed": false, "kind": "int", "endian": "little"},
    "unsigned char": {"size": 1, "signed": false, "kind": "int", "endian": "little"}
  },
  "user_types": {
    "_ADDRESS_OBJECT": {"size": 360, "kind": "struct", "fields": {
      "LocalIpAddress": {"offset": 44, "type": {"kind": "array", "count": 4,
                         "subtype": {"kind": "base", "name": "unsigned char"}}},
      "LocalPort": {"offset": 48, "type": {"kind": "base", "name": "unsigned short"}},
      "Protocol": {"offset": 50, "type": {"kind": "base", "name": "unsigned short"}},
      "Pid": {"offset": 328, "type": {"kind": "base", "name": "unsigned long"}},
      "CreateTime": {"offset": 344, "type": {"kind": "base", "name": "unsigned long long"}}
    }},
    "_TCPT_OBJECT": {"size": 400, "kind": "struct", "fields": {
      "RemoteIpAddress": {"offset": 12, "type": {"kind": "array", "count": 4,
                          "subtype": {"kind": "base", "name": "unsigned char"}}},
      "LocalIpAddress": {"offset": 16, "type": {"kind": "array", "count": 4,
                         "subtype": {"kind": "base", "name": "unsigned char"}}},
      "RemotePort": {"offset": 20, "type": {"kind": "base", "name": "unsigned short"}},
      "LocalPort": {"offset": 22, "type": {"kind": "base", "name": "unsigned short"}},
      "Pid": {"offset": 24, "type": {"kind": "base", "name": "unsigned long"}}
    }}
  },
  "enums": {},
  "symbols": {}
}"#;

/// Members this stage reads, proved to exist before any of them is read.
const ADDRESS_OBJECT_MEMBERS: &[&str] = &[
    "LocalIpAddress",
    "LocalPort",
    "Protocol",
    "Pid",
    "CreateTime",
];

/// Members `_TCPT_OBJECT` must have.
const TCPT_OBJECT_MEMBERS: &[&str] = &[
    "LocalIpAddress",
    "LocalPort",
    "RemoteIpAddress",
    "RemotePort",
    "Pid",
];

/// What one build's `_POOL_HEADER.PoolType` says about an allocation.
///
/// Named rather than left as a pair of parity tests because the parity means
/// opposite things either side of Vista, and a stage that gets it backwards
/// silently keeps only the freed allocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolState {
    /// Allocated from non-paged pool, which is where tcpip.sys puts these.
    NonPaged,
    /// Allocated from paged pool. Not one of these objects.
    Paged,
    /// Freed. Still the historical endpoint an examiner wants, so admitted.
    Freed,
}

/// Read a Windows XP `_POOL_HEADER.PoolType` in the direction XP encodes it.
///
/// XP's `ExAllocatePoolWithTag` stores `POOL_TYPE + 1`, and the `POOL_TYPE`
/// enumeration alternates non-paged and paged: `NonPagedPool` 0, `PagedPool` 1,
/// `NonPagedPoolMustSucceed` 2, ..., `NonPagedPoolCacheAligned` 4,
/// `PagedPoolCacheAligned` 5. So a stored **odd** value is a non-paged
/// allocation and a stored **even, non-zero** value is a paged one. Zero is a
/// block that has been freed and not yet reused, which is exactly the torn-down
/// connection this sweep exists to recover.
pub fn legacy_pool_state(pool_type: u64) -> PoolState {
    if pool_type == 0 {
        PoolState::Freed
    } else if pool_type % 2 == 1 {
        PoolState::NonPaged
    } else {
        PoolState::Paged
    }
}

/// The layout knowledge one pre-Vista image's endpoints are decoded through.
///
/// Built once per image, and refused at construction when the build family has
/// no confirmed layout — never at candidate three thousand, having already
/// emitted rows read at another family's offsets.
#[derive(Debug, Clone)]
pub struct LegacySymbols {
    /// The confirmed layout this image matched.
    layout: LegacyLayout,
    /// tcpip.sys's two structures, compiled from [`LegacyLayout::isf`].
    network: Arc<SymbolTable>,
    /// The kernel's own table, for `_POOL_HEADER`.
    kernel: Arc<SymbolTable>,
    /// Offset of `PoolTag` inside `_POOL_HEADER`.
    pool_tag_offset: u64,
    /// Size of `_POOL_HEADER`, so a tag hit becomes the object after it.
    pool_header_size: u64,
    /// Pool allocation granularity: eight bytes on 32-bit Windows.
    pool_alignment: u64,
    /// The two tags, in the order the scanner is given them.
    tags: Vec<PoolTag>,
}

impl LegacySymbols {
    /// Resolve the pre-Vista layout for this image, or refuse by name.
    ///
    /// # Errors
    ///
    /// [`NetError::BuildUnknown`] when no build number was established, and
    /// [`NetError::Unsupported`] naming the family when it has no confirmed
    /// layout, when the kernel table cannot describe `_POOL_HEADER`, or when the
    /// declared layout does not compile. None of those is an empty endpoint
    /// list.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, NetError> {
        let kernel = Arc::clone(&profile.symbols);
        let pointer_size = kernel.pointer_size();
        let layout = select_layout(&profile.build, pointer_size)?;

        let source =
            seance_symbols::load_slice(layout.isf.as_bytes(), &DecompressLimits::default())
                .map_err(|err| {
                    NetError::unsupported(format!(
                        "the declared {} layout could not be read: {err}",
                        layout.family
                    ))
                })?;
        let network = Arc::new(
            SymbolTable::compile_source(source, &CompileOptions::default()).map_err(|err| {
                NetError::unsupported(format!(
                    "the declared {} layout was refused by the symbol-table admission gates, so \
                     it cannot be read through: {err}",
                    layout.family
                ))
            })?,
        );

        let network_pointer = network.pointer_size();
        if network_pointer != pointer_size {
            return Err(NetError::PointerWidthMismatch {
                kernel: pointer_size,
                network: network_pointer,
            });
        }

        require_legacy(&network, TYPE_ADDRESS_OBJECT, ADDRESS_OBJECT_MEMBERS)?;
        require_legacy(&network, TYPE_TCPT_OBJECT, TCPT_OBJECT_MEMBERS)?;
        super::require(
            &kernel,
            TYPE_POOL_HEADER,
            &[POOL_TAG_MEMBER, "BlockSize", "PoolType"],
        )?;

        let pool_tag_offset = kernel.member_offset(TYPE_POOL_HEADER, POOL_TAG_MEMBER)?;
        let pool_header_size = kernel.size_of(TYPE_POOL_HEADER)?;
        if pool_header_size == 0 {
            return Err(NetError::unsupported(format!(
                "'{TYPE_POOL_HEADER}' declares a size of 0, so the object that follows an \
                 allocation header cannot be located"
            )));
        }

        Ok(LegacySymbols {
            layout,
            network,
            kernel,
            pool_tag_offset,
            pool_header_size,
            // Pool allocation granularity, from the layout's own declared
            // pointer width rather than from a constant, so that adding a
            // 64-bit legacy family cannot leave a 32-bit alignment behind.
            pool_alignment: if layout.pointer_size == 8 { 16 } else { 8 },
            tags: vec![
                PoolTag {
                    tag: TAG_ADDRESS_OBJECT,
                    kind: ObjectKind::AddressObject,
                },
                PoolTag {
                    tag: TAG_TCPT_OBJECT,
                    kind: ObjectKind::TcptObject,
                },
            ],
        })
    }

    /// The layout this image matched, so a report can state which family's
    /// offsets its rows were read at and what that layout was confirmed against.
    pub fn layout(&self) -> LegacyLayout {
        self.layout
    }

    /// tcpip.sys's two structures.
    pub fn network_table(&self) -> &Arc<SymbolTable> {
        &self.network
    }

    /// The kernel's table.
    pub fn kernel_table(&self) -> &Arc<SymbolTable> {
        &self.kernel
    }

    /// The tags this build's tcpip.sys uses.
    pub fn tags(&self) -> &[PoolTag] {
        &self.tags
    }

    /// Which address space this sweep runs against.
    ///
    /// Physical, always: every build with these objects predates the Windows 10
    /// pool layout that made a virtual sweep the right one, and their
    /// allocations are non-paged, so the physical layer reaches every one of
    /// them including those the virtual address space no longer maps.
    pub fn scan_space(&self) -> ScanSpace {
        ScanSpace::Physical
    }

    /// The readers one sweep needs, in the spaces each of them belongs to.
    fn readers(&self, profile: &WindowsProfile) -> Readers {
        Readers::from_tables(
            profile,
            Arc::clone(&self.network),
            Arc::clone(&self.kernel),
            self.scan_space(),
        )
    }
}

/// Pick the layout confirmed for this image's build family, or refuse.
fn select_layout(build: &KernelBuild, pointer_size: u64) -> Result<LegacyLayout, NetError> {
    // The build *number* is not what selects the layout — the family is — but a
    // build whose number was never established is one whose version fields were
    // not read from a structure this code trusts either, and every other stage
    // in this module refuses that rather than proceeding on two of three facts.
    if build.build.is_none() {
        return Err(NetError::BuildUnknown);
    }
    LEGACY_LAYOUTS
        .iter()
        .find(|layout| {
            layout.major == build.major
                && layout.minor == build.minor
                && layout.pointer_size == pointer_size
        })
        .copied()
        .ok_or_else(|| unsupported_family(build, pointer_size))
}

/// The refusal for a pre-Vista family with no confirmed layout.
///
/// It says what is missing rather than what was found, because the difference
/// between "this stage has no layout for Server 2003" and "this machine had no
/// network activity" is the entire point.
fn unsupported_family(build: &KernelBuild, pointer_size: u64) -> NetError {
    let known = LEGACY_LAYOUTS
        .iter()
        .map(|layout| layout.family)
        .collect::<Vec<_>>()
        .join(", ");
    NetError::unsupported(format!(
        "Windows {}.{} with {pointer_size}-byte pointers predates the TcpE/TcpL/UdpA pool tags, \
         and its tcpip.sys tracks endpoints in _ADDRESS_OBJECT and _TCPT_OBJECT structures whose \
         layout this stage has confirmed for {known} only. Those members moved between families \
         and are in no published symbol table, so decoding this one at another family's offsets \
         would produce plausible addresses, ports and PIDs rather than fail. This is not an \
         absence of network activity",
        build.major, build.minor
    ))
}

/// Prove a type and its members exist before anything is read through them.
fn require_legacy(table: &SymbolTable, type_name: &str, members: &[&str]) -> Result<(), NetError> {
    if !table.has_type(type_name) {
        return Err(NetError::unsupported(format!(
            "the declared legacy layout has no '{type_name}' type"
        )));
    }
    for member in members {
        if !table.has_member(type_name, member) {
            return Err(NetError::unsupported(format!(
                "the declared legacy '{type_name}' has no '{member}' member, so that field \
                 cannot be read at any offset"
            )));
        }
    }
    Ok(())
}

/// Sweep physical memory for Windows XP's network objects.
///
/// # What an examiner learns
///
/// Every endpoint the machine had bound and every TCP connection whose control
/// block is still in the image, including connections torn down before
/// acquisition: `TCPT` allocations survive in freed pool, and this sweep admits
/// them.
///
/// # What a wrong answer looks like
///
/// A row whose local and remote halves are the other way round — which turns a
/// laptop browsing the web into a machine serving it — or a row read at Server
/// 2003's offsets, which produces a legal address and a legal port from adjacent
/// memory. Both are refusals rather than best efforts: the first by the member
/// names being confirmed against the machine's own address objects, the second
/// by the layout table being keyed on the build family it was confirmed on.
///
/// # Errors
///
/// Only for failures that make the whole sweep meaningless. A candidate that
/// failed validation is a rejection, counted in
/// [`NetscanOutcome::rejected_total`], not an error.
pub fn legacy_netscan(
    profile: &WindowsProfile,
    symbols: &LegacySymbols,
    config: &NetscanConfig,
) -> Result<NetscanOutcome, NetError> {
    let space = symbols.scan_space();
    let readers = symbols.readers(profile);
    let layer = Arc::clone(&profile.physical);

    let needles: Vec<&[u8]> = symbols.tags.iter().map(|t| t.tag.as_bytes()).collect();
    let scanner = MultiStringScanner::new("windows-xp-network-pool-tags", needles)?;
    let swept: Option<Range<u64>> = config.range.clone();
    let outcome = match &swept {
        Some(range) => scan_range(layer.as_ref(), &scanner, range.clone(), &config.scan)?,
        None => scan_layer(layer.as_ref(), &scanner, &config.scan)?,
    };

    let mut endpoints: Vec<NetworkEndpoint> = Vec::new();
    let mut rejected: Vec<Rejected> = Vec::new();
    let mut rejected_total = 0usize;
    let mut truncated = false;
    let mut candidates = 0usize;

    for hit in &outcome.hits {
        let Some(tag) = symbols.tags.get(hit.pattern_id as usize).copied() else {
            rejected_total = rejected_total.saturating_add(1);
            push_rejection(
                &mut rejected,
                config.max_recorded_rejections,
                Rejected {
                    address: hit.address,
                    tag: "?",
                    reason: format!(
                        "the scanner reported pattern {}, which was never submitted",
                        hit.pattern_id
                    ),
                },
            );
            continue;
        };
        candidates = candidates.saturating_add(1);

        if endpoints.len() >= config.max_endpoints {
            truncated = true;
            break;
        }

        match legacy_examine(&readers, symbols, tag, hit.address) {
            Ok(row) => endpoints.push(row),
            Err(reason) => {
                rejected_total = rejected_total.saturating_add(1);
                push_rejection(
                    &mut rejected,
                    config.max_recorded_rejections,
                    Rejected {
                        address: hit.address,
                        tag: tag.tag,
                        reason,
                    },
                );
            }
        }
    }

    endpoints.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| a.protocol.cmp(&b.protocol))
    });

    let mut incomplete = Vec::new();
    if truncated {
        incomplete.push(Incomplete::new(
            IncompleteReason::CapReached,
            format!(
                "the sweep stopped at its cap of {} endpoints; the image holds more",
                config.max_endpoints
            ),
        ));
    }
    if !outcome.is_complete() {
        incomplete.push(Incomplete::new(
            IncompleteReason::ShortRead,
            format!(
                "{} byte(s) of the physical address space could not be swept, so an endpoint \
                 lying in them would not appear here",
                outcome.unread_bytes
            ),
        ));
    }
    if rejected_total > rejected.len() {
        incomplete.push(Incomplete::new(
            IncompleteReason::CapReached,
            format!(
                "{rejected_total} candidates were rejected and only {} are listed individually",
                rejected.len()
            ),
        ));
    }

    Ok(NetscanOutcome {
        endpoints,
        rejected,
        rejected_total,
        candidates,
        space,
        swept,
        scan: outcome,
        truncated,
        incomplete,
    })
}

/// Turn one tag match into a row, or into the reason it is not one.
fn legacy_examine(
    readers: &Readers,
    symbols: &LegacySymbols,
    tag: PoolTag,
    tag_address: u64,
) -> Result<NetworkEndpoint, String> {
    let pool_base = tag_address
        .checked_sub(symbols.pool_tag_offset)
        .ok_or_else(|| {
            format!(
                "the tag lies {} byte(s) into a pool header, which would place the allocation \
                 below address zero",
                symbols.pool_tag_offset
            )
        })?;
    let object_address = pool_base
        .checked_add(symbols.pool_header_size)
        .ok_or_else(|| {
            "the object after the pool header would lie past the top of the address space"
                .to_string()
        })?;

    let header = readers
        .pool
        .object(pool_base, TYPE_POOL_HEADER)
        .map_err(|err| format!("the pool header could not be read: {err}"))?;
    let block_size = header
        .int("BlockSize")
        .map_err(|err| format!("{TYPE_POOL_HEADER}.BlockSize could not be read: {err}"))?
        .as_u64()
        .ok_or_else(|| format!("{TYPE_POOL_HEADER}.BlockSize is negative"))?;
    let pool_type = header
        .int("PoolType")
        .map_err(|err| format!("{TYPE_POOL_HEADER}.PoolType could not be read: {err}"))?
        .as_u64()
        .ok_or_else(|| format!("{TYPE_POOL_HEADER}.PoolType is negative"))?;

    let pool_state = legacy_pool_state(pool_type);
    if pool_state == PoolState::Paged {
        return Err(format!(
            "the allocation is paged pool (XP PoolType {pool_type}, which is even and non-zero), \
             and tcpip.sys's endpoints are allocated non-paged"
        ));
    }

    let type_name = tag.kind.type_name();
    let type_size = readers
        .network
        .size_of(type_name)
        .map_err(|err| format!("'{type_name}' has no declared size: {err}"))?
        .bytes();
    let allocation = block_size.saturating_mul(symbols.pool_alignment);
    let needed = symbols.pool_header_size.saturating_add(type_size);
    if allocation < needed {
        return Err(format!(
            "the allocation is {allocation} byte(s) and a '{type_name}' with its pool header is \
             {needed}, so the object cannot fit in it"
        ));
    }

    let verdict = readers
        .network
        .check_struct_aligned(object_address, type_name, symbols.pool_alignment)
        .map_err(|err| {
            format!("'{type_name}' could not be checked at {object_address:#x}: {err}")
        })?;
    let mut notes = Vec::new();
    for failure in &verdict.failures {
        match failure {
            // Neither of these structures has a pointer member this stage reads,
            // so a non-canonical one is a fact about the rest of the allocation
            // rather than about the row. An unreadable member is recorded for the
            // same reason the modern sweep records it: a freed allocation
            // legitimately has scrubbed bytes and is still the historical
            // endpoint an examiner wants to see.
            PlausibilityFailure::NonCanonicalPointer { member, value } => notes.push(format!(
                "'{member}' holds {value:#x}, which no canonical address space can contain"
            )),
            PlausibilityFailure::Unreadable { member, detail } => {
                notes.push(format!("'{member}' could not be read: {detail}"))
            }
            other => return Err(other.to_string()),
        }
    }
    if pool_state == PoolState::Freed {
        notes.push(
            "the allocation has been freed, so this endpoint had been torn down before the image \
             was taken"
                .to_string(),
        );
    }

    let object = readers
        .network
        .object(object_address, type_name)
        .map_err(|err| format!("'{type_name}' could not be built at {object_address:#x}: {err}"))?;

    match tag.kind {
        ObjectKind::AddressObject => decode_address_object(&object, tag, object_address, notes),
        ObjectKind::TcptObject => decode_tcpt_object(&object, tag, object_address, notes),
        // Unreachable: `symbols.tags` holds these two and nothing else. Written
        // out so that adding a third tag is a compile error here rather than a
        // silent decode at the wrong structure's offsets.
        ObjectKind::TcpEndpoint | ObjectKind::TcpListener | ObjectKind::UdpEndpoint => {
            Err(format!(
                "'{}' is a post-Vista object and is not decoded by the legacy stage",
                tag.kind.type_name()
            ))
        }
    }
}

/// One `_ADDRESS_OBJECT` as a row.
fn decode_address_object(
    object: &Obj,
    tag: PoolTag,
    address: u64,
    mut notes: Vec<String>,
) -> Result<NetworkEndpoint, String> {
    let number = object
        .int("Protocol")
        .map_err(|err| format!("'{TYPE_ADDRESS_OBJECT}.Protocol' could not be read: {err}"))?
        .as_u64()
        .ok_or_else(|| format!("'{TYPE_ADDRESS_OBJECT}.Protocol' is negative"))?;
    // Zero is IPv6's hop-by-hop header and is never a socket's protocol; above
    // 255 is not a protocol number at all. Both mean the four bytes that matched
    // the tag were the only thing about this candidate that did.
    if number == 0 || number > u64::from(MAX_IP_PROTOCOL) {
        return Err(format!(
            "the IP protocol number is {number}, and a socket's is between 1 and {MAX_IP_PROTOCOL}"
        ));
    }
    let number = number as u16;
    let protocol = match number {
        IPPROTO_TCP => Protocol::TcpV4,
        IPPROTO_UDP => Protocol::UdpV4,
        other => Protocol::OtherV4 { number: other },
    };

    let local_port = read_port(object, "LocalPort")?;
    let local_address = format_ipv4(&object.bytes("LocalIpAddress").map_err(|err| {
        format!("'{TYPE_ADDRESS_OBJECT}.LocalIpAddress' could not be read: {err}")
    })?)?;
    let owner_pid = read_legacy_pid(object, &mut notes);
    let created = read_create_time(object, &mut notes);

    // The last-resort test, and the same one the modern decoder applies: an
    // `_ADDRESS_OBJECT` is created by the kernel with both a creation time and
    // an owning process, so a candidate with neither a believable time nor a
    // plausible PID has nothing corroborating it but four matching bytes.
    if created.is_none() && !plausible_owner(owner_pid) {
        return Err(format!(
            "neither a believable creation time nor a plausible owning process could be read \
             (PID {owner_pid:?})"
        ));
    }

    Ok(NetworkEndpoint {
        offset: address,
        tag: tag.tag,
        kind: tag.kind,
        protocol,
        local_address: Some(local_address),
        local_port,
        // A listener's peer really is the unspecified address until a client
        // connects, at which point tcpip.sys creates a separate `_TCPT_OBJECT`
        // carrying the peer -- the same relationship, and so the same rendering,
        // as the modern decoder's `_TCP_LISTENER`. Anything that is not TCP has
        // no peer at all and no state to be in.
        remote_address: if number == IPPROTO_TCP {
            Some(unspecified_v4())
        } else {
            None
        },
        remote_port: if number == IPPROTO_TCP { Some(0) } else { None },
        state: if number == IPPROTO_TCP {
            SocketState::Listening
        } else {
            SocketState::NotApplicable
        },
        owner_pid,
        // XP's `_ADDRESS_OBJECT` holds a PID and no `_EPROCESS` pointer, so
        // there is no image name in it. Resolving the PID against a process list
        // is a different stage's answer with a different provenance; inventing
        // one here would attach a name to a number this object never named.
        owner_process: None,
        created,
        notes,
    })
}

/// One `_TCPT_OBJECT` as a row.
fn decode_tcpt_object(
    object: &Obj,
    tag: PoolTag,
    address: u64,
    mut notes: Vec<String>,
) -> Result<NetworkEndpoint, String> {
    let local_port = read_port(object, "LocalPort")?;
    let remote_port = read_port(object, "RemotePort")?;
    // A TCP control block always has both ports assigned; a zero at either end
    // is an unwritten field rather than a connection to port zero.
    if local_port == 0 || remote_port == 0 {
        return Err(format!(
            "the control block has local port {local_port} and remote port {remote_port}, and an \
             established connection has neither at zero"
        ));
    }

    let local_address =
        format_ipv4(&object.bytes("LocalIpAddress").map_err(|err| {
            format!("'{TYPE_TCPT_OBJECT}.LocalIpAddress' could not be read: {err}")
        })?)?;
    let remote_address = format_ipv4(&object.bytes("RemoteIpAddress").map_err(|err| {
        format!("'{TYPE_TCPT_OBJECT}.RemoteIpAddress' could not be read: {err}")
    })?)?;

    let owner_pid = read_legacy_pid(object, &mut notes);
    // A `_TCPT_OBJECT` carries no creation time and no state member, so the PID
    // is the only field corroborating the addresses. It has to hold up.
    if !plausible_owner(owner_pid) {
        return Err(format!(
            "no plausible owning process could be read (PID {owner_pid:?}), and a control block \
             carries no creation time or state to corroborate its addresses"
        ));
    }

    Ok(NetworkEndpoint {
        offset: address,
        tag: tag.tag,
        kind: tag.kind,
        protocol: Protocol::TcpV4,
        local_address: Some(local_address),
        local_port,
        remote_address: Some(remote_address),
        remote_port: Some(remote_port),
        // XP's control block has no state member in the part of it whose layout
        // has been confirmed. "CLOSED" or "ESTABLISHED" here would be a claim
        // about the connection that the object did not make, so the state is
        // carried as the absence it is.
        state: SocketState::NotApplicable,
        owner_pid,
        owner_process: None,
        created: None,
        notes,
    })
}

/// The unspecified IPv4 address, `0.0.0.0`.
///
/// Written as the constant rather than as a literal so that a listener's peer
/// here and a listener's peer in the modern decoder cannot drift into two
/// different strings for the same fact.
fn unspecified_v4() -> String {
    std::net::Ipv4Addr::UNSPECIFIED.to_string()
}

/// The `Pid` member, or nothing plus a note.
///
/// Never a guess: a connection whose owner cannot be read is still evidence of a
/// connection, and attributing it to the wrong process would not be.
fn read_legacy_pid(object: &Obj, notes: &mut Vec<String>) -> Option<u64> {
    match object.int("Pid") {
        Ok(value) => match value.as_u64() {
            Some(pid) => Some(pid),
            None => {
                notes.push(format!(
                    "'{}.Pid' is negative, so it is not a process id",
                    object.type_name()
                ));
                None
            }
        },
        Err(err) => {
            notes.push(format!(
                "'{}.Pid' could not be read: {err}",
                object.type_name()
            ));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use seance_memory::{Architecture, MemoryLayer};

    use super::super::test_support::Image;
    use super::super::{NetscanConfig, NetstatConfig, NetworkPlan, NetworkSymbols};
    use super::*;
    use crate::profile::{Evidence, Found, KernelBuild, WindowsProfile};

    /// A synthetic 32-bit kernel ISF carrying Windows XP's real `_POOL_HEADER`.
    ///
    /// The bitfields are declared exactly as XP's own PDB declares them —
    /// `BlockSize` and `PoolType` packed into the `unsigned short` at offset 2 —
    /// rather than as two convenient whole members. That is deliberate: the
    /// packing is where an XP header stops looking like a Vista one, and a
    /// fixture that flattened it would prove nothing about the image this stage
    /// exists to read.
    const XP_KERNEL_ISF: &str = r#"{
      "metadata": {
        "format": "6.2.0",
        "producer": {"name": "seance-test", "version": "1.0.0"},
        "windows": {"pdb": {"GUID": "BB1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                            "database": "ntoskrnl.pdb", "machine_type": 332}}
      },
      "base_types": {
        "pointer": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
        "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
        "unsigned short": {"size": 2, "signed": false, "kind": "int", "endian": "little"},
        "unsigned char": {"size": 1, "signed": false, "kind": "int", "endian": "little"}
      },
      "user_types": {
        "_POOL_HEADER": {"size": 8, "kind": "struct", "fields": {
          "PreviousSize": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 0,
            "bit_length": 9, "type": {"kind": "base", "name": "unsigned short"}}},
          "PoolIndex": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 9,
            "bit_length": 7, "type": {"kind": "base", "name": "unsigned short"}}},
          "BlockSize": {"offset": 2, "type": {"kind": "bitfield", "bit_position": 0,
            "bit_length": 9, "type": {"kind": "base", "name": "unsigned short"}}},
          "PoolType": {"offset": 2, "type": {"kind": "bitfield", "bit_position": 9,
            "bit_length": 7, "type": {"kind": "base", "name": "unsigned short"}}},
          "PoolTag": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}}
        }},
        "_EPROCESS": {"size": 64, "kind": "struct", "fields": {
          "UniqueProcessId": {"offset": 0, "type": {"kind": "pointer",
            "subtype": {"kind": "base", "name": "unsigned char"}}},
          "ImageFileName": {"offset": 4, "type": {"kind": "array", "count": 15,
            "subtype": {"kind": "base", "name": "unsigned char"}}}
        }}
      },
      "enums": {},
      "symbols": {}
    }"#;

    /// Offsets [`XP_X86_ISF`] declares, restated so a test writes a field where
    /// the table says it is and a mistake in one shows up as a failure rather
    /// than as agreement.
    const AO_LOCAL_IP: u64 = 0x2c;
    const AO_LOCAL_PORT: u64 = 0x30;
    const AO_PROTOCOL: u64 = 0x32;
    const AO_PID: u64 = 0x148;
    const AO_CREATE_TIME: u64 = 0x158;
    const AO_SIZE: u64 = 360;

    const TCPT_REMOTE_IP: u64 = 0x0c;
    const TCPT_LOCAL_IP: u64 = 0x10;
    const TCPT_REMOTE_PORT: u64 = 0x14;
    const TCPT_LOCAL_PORT: u64 = 0x16;
    const TCPT_PID: u64 = 0x18;
    const TCPT_SIZE: u64 = 400;

    /// Windows XP's `_POOL_HEADER` is eight bytes with the tag at four.
    const POOL_HEADER_SIZE: u64 = 8;

    /// `NonPagedPoolCacheAligned` + 1, which is what a live `_ADDRESS_OBJECT`
    /// header holds on Windows XP. Odd, and therefore non-paged.
    const XP_NON_PAGED: u16 = 5;

    /// A freed allocation. Still the endpoint an examiner wants.
    const XP_FREED: u16 = 0;

    /// `PagedPool` + 1. Even and non-zero, and therefore paged.
    const XP_PAGED: u16 = 2;

    /// 2005-06-25T16:48:00Z, inside the uptime of the image the layout was
    /// confirmed against.
    const CREATE_TIME: u64 = 127_640_764_800_000_000;

    fn table(json: &str) -> Arc<seance_symbols::SymbolTable> {
        super::super::test_support::table(json)
    }

    /// A 32-bit pre-Vista profile over one layer.
    fn xp_profile(layer: Arc<dyn MemoryLayer>, major: u32, minor: u32) -> WindowsProfile {
        WindowsProfile {
            kernel_space: Arc::clone(&layer),
            physical: layer,
            symbols: table(XP_KERNEL_ISF),
            pagefiles: Vec::new(),
            dtb: Found::new(0x39000, Evidence::Confirmed),
            kernel_base: Found::new(0x1_0000, Evidence::Confirmed),
            kdbg: None,
            build: KernelBuild {
                pdb: "ntoskrnl.pdb".into(),
                guid: "B".repeat(32),
                age: 1,
                build_lab: Some("2600.xpsp_sp2_gdr.050301-1519".into()),
                major,
                minor,
                build: Some(2600),
                build_source: Some("nt_build_lab"),
            },
            architecture: Architecture::X86,
        }
    }

    /// Write an XP pool header: `BlockSize` and `PoolType` packed into the
    /// `unsigned short` at offset two, exactly as the kernel packs them.
    fn xp_pool_header(image: &mut Image, base: u64, tag: &[u8; 4], blocks: u16, pool_type: u16) {
        image.put_u16(base, 0);
        image.put_u16(base + 2, (blocks & 0x1ff) | (pool_type << 9));
        image.write(base + 4, tag);
    }

    /// How many eight-byte blocks an allocation of `bytes` occupies.
    fn blocks_for(bytes: u64) -> u16 {
        ((POOL_HEADER_SIZE + bytes).div_ceil(8)) as u16
    }

    /// Lay one `_ADDRESS_OBJECT` into an image and hand back its pool base.
    #[allow(clippy::too_many_arguments)]
    fn address_object(
        image: &mut Image,
        pool_base: u64,
        pool_type: u16,
        ip: [u8; 4],
        port: u16,
        protocol: u16,
        pid: u32,
        create_time: u64,
    ) -> u64 {
        xp_pool_header(image, pool_base, b"TCPA", blocks_for(AO_SIZE), pool_type);
        let object = pool_base + POOL_HEADER_SIZE;
        image.write(object + AO_LOCAL_IP, &ip);
        image.put_port(object + AO_LOCAL_PORT, port);
        image.put_u16(object + AO_PROTOCOL, protocol);
        image.put_u32(object + AO_PID, pid);
        image.put_u64(object + AO_CREATE_TIME, create_time);
        object
    }

    /// Lay one `_TCPT_OBJECT` into an image and hand back its object address.
    #[allow(clippy::too_many_arguments)]
    fn tcpt_object(
        image: &mut Image,
        pool_base: u64,
        pool_type: u16,
        local_ip: [u8; 4],
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
        pid: u32,
    ) -> u64 {
        xp_pool_header(image, pool_base, b"TCPT", blocks_for(TCPT_SIZE), pool_type);
        let object = pool_base + POOL_HEADER_SIZE;
        image.write(object + TCPT_LOCAL_IP, &local_ip);
        image.write(object + TCPT_REMOTE_IP, &remote_ip);
        image.put_port(object + TCPT_LOCAL_PORT, local_port);
        image.put_port(object + TCPT_REMOTE_PORT, remote_port);
        image.put_u32(object + TCPT_PID, pid);
        object
    }

    fn sweep(profile: &WindowsProfile) -> NetscanOutcome {
        let symbols = LegacySymbols::from_profile(profile).expect("a confirmed XP layout");
        legacy_netscan(profile, &symbols, &NetscanConfig::default()).expect("the sweep runs")
    }

    // ── the layout itself ───────────────────────────────────────────────────

    #[test]
    fn the_declared_xp_layout_compiles_and_keeps_its_confirmed_offsets() {
        let network = table(XP_X86_ISF);
        for (type_name, member, offset) in [
            (TYPE_ADDRESS_OBJECT, "LocalIpAddress", AO_LOCAL_IP),
            (TYPE_ADDRESS_OBJECT, "LocalPort", AO_LOCAL_PORT),
            (TYPE_ADDRESS_OBJECT, "Protocol", AO_PROTOCOL),
            (TYPE_ADDRESS_OBJECT, "Pid", AO_PID),
            (TYPE_ADDRESS_OBJECT, "CreateTime", AO_CREATE_TIME),
            (TYPE_TCPT_OBJECT, "RemoteIpAddress", TCPT_REMOTE_IP),
            (TYPE_TCPT_OBJECT, "LocalIpAddress", TCPT_LOCAL_IP),
            (TYPE_TCPT_OBJECT, "RemotePort", TCPT_REMOTE_PORT),
            (TYPE_TCPT_OBJECT, "LocalPort", TCPT_LOCAL_PORT),
            (TYPE_TCPT_OBJECT, "Pid", TCPT_PID),
        ] {
            assert_eq!(
                network
                    .member_offset(type_name, member)
                    .unwrap_or_else(|err| panic!("'{type_name}.{member}': {err}")),
                offset,
                "'{type_name}.{member}' moved; every row this stage emits is read at these \
                 offsets and they were confirmed against a real image"
            );
        }
        assert_eq!(
            network.size_of(TYPE_ADDRESS_OBJECT).expect("a size"),
            AO_SIZE
        );
        assert_eq!(
            network.size_of(TYPE_TCPT_OBJECT).expect("a size"),
            TCPT_SIZE
        );
        assert_eq!(network.pointer_size(), 4);
    }

    // ── the pool-type inversion, which is the whole reason for a second stage ─

    #[test]
    fn windows_xp_encodes_non_paged_pool_as_an_odd_pool_type() {
        // The Vista rule is the other way round: there, even and non-zero is
        // non-paged. Reading XP through it keeps only the freed allocations,
        // which reads as a machine that had closed every connection.
        assert_eq!(legacy_pool_state(1), PoolState::NonPaged);
        assert_eq!(
            legacy_pool_state(u64::from(XP_NON_PAGED)),
            PoolState::NonPaged
        );
        assert_eq!(legacy_pool_state(u64::from(XP_FREED)), PoolState::Freed);
        assert_eq!(legacy_pool_state(u64::from(XP_PAGED)), PoolState::Paged);
        assert_eq!(legacy_pool_state(6), PoolState::Paged);
    }

    #[test]
    fn a_live_xp_endpoint_is_kept_rather_than_rejected_as_paged() {
        let mut image = Image::new();
        address_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [0, 0, 0, 0],
            161,
            IPPROTO_UDP,
            1424,
            CREATE_TIME,
        );
        let profile = xp_profile(image.layer(), 5, 1);
        let outcome = sweep(&profile);

        assert_eq!(outcome.rejected_total, 0, "{:?}", outcome.rejected);
        assert_eq!(outcome.endpoints.len(), 1);
        let row = &outcome.endpoints[0];
        assert_eq!(row.protocol, Protocol::UdpV4);
        assert_eq!(row.local_address.as_deref(), Some("0.0.0.0"));
        assert_eq!(row.local_port, 161);
        assert_eq!(row.owner_pid, Some(1424));
        assert_eq!(row.remote_address, None);
        assert_eq!(row.state, SocketState::NotApplicable);
        assert_eq!(
            row.created.as_ref().map(|t| t.filetime),
            Some(CREATE_TIME),
            "the creation time is what separates a bound socket from four \
             matching bytes"
        );
    }

    #[test]
    fn a_paged_allocation_under_the_same_tag_is_rejected() {
        let mut image = Image::new();
        address_object(
            &mut image,
            0x2000,
            XP_PAGED,
            [0, 0, 0, 0],
            161,
            IPPROTO_UDP,
            1424,
            CREATE_TIME,
        );
        let profile = xp_profile(image.layer(), 5, 1);
        let outcome = sweep(&profile);

        assert!(outcome.endpoints.is_empty());
        assert_eq!(outcome.rejected_total, 1);
        assert!(
            outcome.rejected[0].reason.contains("paged pool"),
            "{}",
            outcome.rejected[0].reason
        );
    }

    #[test]
    fn a_freed_connection_is_recovered_and_says_it_was_freed() {
        let mut image = Image::new();
        tcpt_object(
            &mut image,
            0x2000,
            XP_FREED,
            [192, 168, 2, 7],
            1115,
            [207, 126, 123, 29],
            80,
            1916,
        );
        let profile = xp_profile(image.layer(), 5, 1);
        let outcome = sweep(&profile);

        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);
        let row = &outcome.endpoints[0];
        assert!(
            row.notes.iter().any(|note| note.contains("freed")),
            "a torn-down connection must say so rather than look live: {:?}",
            row.notes
        );
    }

    // ── the two decoders ────────────────────────────────────────────────────

    #[test]
    fn a_tcp_control_block_keeps_local_and_remote_the_right_way_round() {
        let mut image = Image::new();
        tcpt_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [192, 168, 2, 7],
            1115,
            [207, 126, 123, 29],
            80,
            1916,
        );
        let profile = xp_profile(image.layer(), 5, 1);
        let outcome = sweep(&profile);

        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);
        let row = &outcome.endpoints[0];
        // Reading the pair the other way round turns a laptop browsing the web
        // into a machine serving it, and both readings are legal addresses.
        assert_eq!(row.local_address.as_deref(), Some("192.168.2.7"));
        assert_eq!(row.local_port, 1115);
        assert_eq!(row.remote_address.as_deref(), Some("207.126.123.29"));
        assert_eq!(row.remote_port, Some(80));
        assert_eq!(row.protocol, Protocol::TcpV4);
        assert_eq!(row.owner_pid, Some(1916));
        assert_eq!(row.kind, ObjectKind::TcptObject);
    }

    #[test]
    fn ports_are_read_in_network_byte_order() {
        let mut image = Image::new();
        // Port 80 is the bytes 00 50. Read little-endian that is 20480, which is
        // a legal ephemeral port and so survives review.
        address_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [0, 0, 0, 0],
            80,
            IPPROTO_TCP,
            580,
            CREATE_TIME,
        );
        let profile = xp_profile(image.layer(), 5, 1);
        let outcome = sweep(&profile);

        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);
        assert_eq!(outcome.endpoints[0].local_port, 80);
        assert_ne!(outcome.endpoints[0].local_port, 20480);
    }

    #[test]
    fn a_tcp_address_object_is_a_listener_and_a_udp_one_is_not() {
        let mut image = Image::new();
        address_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [0, 0, 0, 0],
            445,
            IPPROTO_TCP,
            4,
            CREATE_TIME,
        );
        let profile = xp_profile(image.layer(), 5, 1);
        let outcome = sweep(&profile);

        let row = &outcome.endpoints[0];
        assert_eq!(row.protocol, Protocol::TcpV4);
        assert_eq!(row.state, SocketState::Listening);
        assert_eq!(row.remote_address.as_deref(), Some("0.0.0.0"));
        assert_eq!(row.remote_port, Some(0));
    }

    #[test]
    fn a_raw_socket_keeps_its_protocol_number_instead_of_becoming_tcp() {
        let mut image = Image::new();
        // Protocol 255 on a bound endpoint is a raw socket: a sniffer and
        // backdoor indicator, and the most interesting row on the machine.
        address_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [0, 0, 0, 0],
            0,
            255,
            592,
            CREATE_TIME,
        );
        let profile = xp_profile(image.layer(), 5, 1);
        let outcome = sweep(&profile);

        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);
        let row = &outcome.endpoints[0];
        assert_eq!(row.protocol, Protocol::OtherV4 { number: 255 });
        assert_ne!(row.protocol, Protocol::TcpV4);
        assert_eq!(row.protocol.ip_protocol(), 255);
        assert_eq!(row.state, SocketState::NotApplicable);
        assert_eq!(
            row.to_json()["ip_protocol"],
            serde_json::json!(255),
            "a report showing only 'IPv4' cannot tell a raw socket from a \
             multicast membership"
        );
    }

    // ── candidates that are not endpoints ───────────────────────────────────

    #[test]
    fn a_protocol_number_that_is_not_one_rejects_the_candidate() {
        for protocol in [0u16, 33265] {
            let mut image = Image::new();
            address_object(
                &mut image,
                0x2000,
                XP_NON_PAGED,
                [0, 0, 0, 0],
                1024,
                protocol,
                580,
                CREATE_TIME,
            );
            let profile = xp_profile(image.layer(), 5, 1);
            let outcome = sweep(&profile);

            assert!(outcome.endpoints.is_empty(), "protocol {protocol}");
            assert_eq!(outcome.rejected_total, 1);
            assert!(
                outcome.rejected[0].reason.contains("IP protocol number"),
                "{}",
                outcome.rejected[0].reason
            );
        }
    }

    #[test]
    fn an_address_object_with_neither_a_time_nor_an_owner_is_rejected() {
        let mut image = Image::new();
        address_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [1, 0, 0, 0],
            1280,
            12,
            3_799_288_088,
            0,
        );
        let profile = xp_profile(image.layer(), 5, 1);
        let outcome = sweep(&profile);

        assert!(outcome.endpoints.is_empty());
        assert_eq!(outcome.rejected_total, 1);
        assert!(
            outcome.rejected[0]
                .reason
                .contains("neither a believable creation time"),
            "{}",
            outcome.rejected[0].reason
        );
    }

    #[test]
    fn a_control_block_with_an_implausible_owner_is_rejected() {
        let mut image = Image::new();
        tcpt_object(
            &mut image,
            0x2000,
            XP_FREED,
            [3, 0, 48, 2],
            17985,
            [66, 179, 81, 245],
            20084,
            4_287_933_200,
        );
        let profile = xp_profile(image.layer(), 5, 1);
        let outcome = sweep(&profile);

        assert!(
            outcome.endpoints.is_empty(),
            "a control block carries no creation time and no state, so an \
             implausible PID leaves nothing corroborating its addresses"
        );
        assert_eq!(outcome.rejected_total, 1);
    }

    #[test]
    fn a_control_block_with_a_zero_port_is_rejected() {
        let mut image = Image::new();
        tcpt_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [192, 168, 2, 7],
            0,
            [207, 126, 123, 29],
            80,
            1916,
        );
        let profile = xp_profile(image.layer(), 5, 1);
        let outcome = sweep(&profile);

        assert!(outcome.endpoints.is_empty());
        assert_eq!(outcome.rejected_total, 1);
    }

    #[test]
    fn an_allocation_too_small_to_hold_the_object_is_rejected() {
        let mut image = Image::new();
        address_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [0, 0, 0, 0],
            161,
            IPPROTO_UDP,
            1424,
            CREATE_TIME,
        );
        // Shrink the allocation to eight bytes, keeping every member where it
        // was: the bytes still decode, and the header says they cannot be this
        // object.
        xp_pool_header(&mut image, 0x2000, b"TCPA", 1, XP_NON_PAGED);
        let profile = xp_profile(image.layer(), 5, 1);
        let outcome = sweep(&profile);

        assert!(outcome.endpoints.is_empty());
        assert_eq!(outcome.rejected_total, 1);
        assert!(
            outcome.rejected[0].reason.contains("cannot fit"),
            "{}",
            outcome.rejected[0].reason
        );
    }

    // ── which build gets which decoder ──────────────────────────────────────

    #[test]
    fn server_2003_is_refused_by_name_rather_than_decoded_at_xp_offsets() {
        let mut image = Image::new();
        address_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [0, 0, 0, 0],
            161,
            IPPROTO_UDP,
            1424,
            CREATE_TIME,
        );
        let profile = xp_profile(image.layer(), 5, 2);
        let err = LegacySymbols::from_profile(&profile)
            .expect_err("Server 2003's layout has not been confirmed");

        let message = err.to_string();
        assert_eq!(err.class(), "unsupported_build");
        assert!(message.contains("Windows 5.2"), "{message}");
        assert!(message.contains("Windows XP (NT 5.1), 32-bit"), "{message}");
        assert!(
            message.contains("This is not an absence of network activity"),
            "the refusal must keep saying what it is not: {message}"
        );
    }

    #[test]
    fn a_64_bit_pre_vista_image_is_refused() {
        // Same family number, different pointer width, and the members move.
        let mut image = Image::new();
        address_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [0, 0, 0, 0],
            161,
            IPPROTO_UDP,
            1424,
            CREATE_TIME,
        );
        let mut profile = xp_profile(image.layer(), 5, 1);
        profile.symbols = table(
            &XP_KERNEL_ISF
                .replace(r#""pointer": {"size": 4"#, r#""pointer": {"size": 8"#)
                .replace(r#""machine_type": 332"#, r#""machine_type": 34404"#),
        );

        let err = LegacySymbols::from_profile(&profile)
            .expect_err("no 64-bit pre-Vista layout has been confirmed");
        assert!(err.to_string().contains("8-byte pointers"), "{err}");
    }

    #[test]
    fn a_build_with_no_number_is_refused_rather_than_assumed() {
        let mut image = Image::new();
        address_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [0, 0, 0, 0],
            161,
            IPPROTO_UDP,
            1424,
            CREATE_TIME,
        );
        let mut profile = xp_profile(image.layer(), 5, 1);
        profile.build.build = None;

        let err = LegacySymbols::from_profile(&profile).expect_err("refused");
        assert_eq!(err.class(), "build_unknown");
    }

    #[test]
    fn the_modern_decoder_still_refuses_windows_xp() {
        let mut image = Image::new();
        address_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [0, 0, 0, 0],
            161,
            IPPROTO_UDP,
            1424,
            CREATE_TIME,
        );
        let profile = xp_profile(image.layer(), 5, 1);
        let err = NetworkSymbols::from_profile(&profile)
            .expect_err("XP has no TcpE/TcpL/UdpA objects to decode");

        let message = err.to_string();
        assert!(
            message.contains("predates the TcpE/TcpL/UdpA pool tags"),
            "{message}"
        );
        assert!(
            message.contains("This is not an absence of network activity"),
            "{message}"
        );
    }

    #[test]
    fn the_plan_sends_each_build_to_the_decoder_that_describes_it() {
        let mut image = Image::new();
        address_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [0, 0, 0, 0],
            161,
            IPPROTO_UDP,
            1424,
            CREATE_TIME,
        );
        let profile = xp_profile(image.layer(), 5, 1);
        let plan = NetworkPlan::from_profile(&profile).expect("XP is planned for");
        assert!(matches!(plan, NetworkPlan::Legacy(_)));
        assert_eq!(plan.scan_space(), ScanSpace::Physical);
        assert_eq!(
            plan.tags().iter().map(|t| t.tag).collect::<Vec<_>>(),
            vec![TAG_ADDRESS_OBJECT, TAG_TCPT_OBJECT],
            "a plan that swept for TcpE on XP would report an idle machine"
        );
    }

    // ── the stage as the orchestrator reaches it ────────────────────────────

    #[test]
    fn the_xp_survey_yields_endpoints_and_declines_to_invent_a_second_view() {
        let mut image = Image::new();
        address_object(
            &mut image,
            0x2000,
            XP_NON_PAGED,
            [0, 0, 0, 0],
            161,
            IPPROTO_UDP,
            1424,
            CREATE_TIME,
        );
        tcpt_object(
            &mut image,
            0x4000,
            XP_NON_PAGED,
            [192, 168, 2, 7],
            1115,
            [207, 126, 123, 29],
            80,
            1916,
        );
        let profile = xp_profile(image.layer(), 5, 1);
        let plan = NetworkPlan::from_profile(&profile).expect("XP is planned for");
        let survey = super::super::survey_network_with(
            &profile,
            &plan,
            &NetscanConfig::default(),
            &NetstatConfig::default(),
        )
        .expect("the XP survey runs");

        assert_eq!(survey.scan.endpoints.len(), 2, "{:?}", survey.scan.rejected);
        assert!(survey.walk.is_none());
        let reason = survey
            .walk_unavailable
            .as_deref()
            .expect("the missing walk must say why");
        assert!(reason.contains("AddrObjTable"), "{reason}");
        assert!(reason.contains("TCBTable"), "{reason}");
        assert!(
            !survey.comparable,
            "with one view there is nothing to subtract, and subtracting from \
             nothing reports every endpoint as hidden"
        );
        assert!(survey.swept_only.is_empty());

        let json = survey.to_json();
        assert_eq!(json["walk"], serde_json::Value::Null);
        assert!(json["layout"]
            .as_str()
            .expect("the layout provenance is on the record")
            .contains("Windows XP (NT 5.1), 32-bit"));
    }
}
