//! Network connections and listening sockets, recovered from tcpip.sys's own
//! kernel objects.
//!
//! Two questions an examiner asks of a memory image are "what was this machine
//! talking to" and "what was it listening on". Neither is answerable from disk:
//! a TCP connection leaves no file, and by the time an image is acquired the
//! connection may already be closed. Both are answerable from RAM, because the
//! TCP/IP stack keeps one pool allocation per endpoint, listener and UDP
//! socket, and those allocations outlive the objects in them.
//!
//! # The two routes, and why both exist
//!
//! * [`netscan`] **scans** physical or kernel memory for the pool tags
//!   tcpip.sys allocates its network objects under — `TcpE`, `TcpL`, `UdpA`
//!   and, from Server 2022 onwards, `TTcb`. It finds objects the kernel no
//!   longer links to: connections torn down before acquisition, and objects a
//!   rootkit unlinked. That is its whole value, and it is why the sweep runs
//!   against a raw address space rather than a list.
//! * [`netstat`](netstat::netstat) **walks** tcpip.sys's partition table and
//!   port pools, which is what the live `netstat` command reads. It is the
//!   cross-view: an object the walk reaches and the sweep does not is a scanning
//!   gap, and an object the sweep finds and the walk does not is either
//!   historical or hidden.
//!
//! Running both and comparing is the finding. Running one and calling it the
//! other is not, so [`netstat`](netstat::netstat) never falls back to
//! [`netscan`]: when tcpip's symbols do not permit the walk, it says so.
//!
//! # What this module refuses to do
//!
//! **It never guesses a layout.** `_TCP_ENDPOINT`, `_TCP_LISTENER` and
//! `_UDP_ENDPOINT` are among the most build-variable structures in Windows —
//! `_TCP_ENDPOINT.Owner` sits at offset 568 on Windows 7 x64, 600 on Windows 10
//! 10240 and 752 on Server 2022 — and they are not in `ntoskrnl`'s symbols at
//! all. Every member is resolved through a symbol table that describes *this*
//! build, and a member the table does not have is an error naming it, never
//! offset zero. A wrong offset here does not look wrong: it produces a row with
//! a plausible IP address, a plausible port and a plausible PID.
//!
//! **It fails closed on builds it cannot decode.** Windows XP and Server 2003
//! predate these pool tags entirely — tcpip.sys there tracks connections in
//! `_ADDRESS_OBJECT` and `_TCPT_OBJECT` structures with no such tags — so
//! [`NetworkSymbols`] still refuses them, and never returns an empty table. An
//! empty table reads as "this machine had no network activity", which is a claim
//! about the evidence that the evidence does not support.
//!
//! Those builds are decoded by [`legacy`] instead, from the `TCPA` and `TCPT`
//! tags their tcpip.sys does allocate under, and only on the one build family
//! whose layout has been confirmed against a real image. Everything else in
//! `major < 6` still refuses, naming the family it would need. Which of the two
//! stages runs is [`NetworkPlan`]'s decision and nothing else's, so there is no
//! path on which an XP object is read at Vista's offsets or the reverse.
//!
//! # Ports are big-endian inside a little-endian structure
//!
//! tcpip.sys stores ports in **network byte order** in structures that are
//! otherwise little-endian. Port 80 is the bytes `00 50`; read as a
//! little-endian `USHORT` that is 20480. The number is plausible — it is a legal
//! ephemeral port — so nothing downstream catches it, and a report saying a
//! process was listening on 20480 when it was serving HTTP is wrong in a way
//! that survives review. [`decode`] therefore reads the two bytes of a port
//! member and interprets them big-endian whatever the symbol table declares,
//! because the byte order is a property of tcpip.sys rather than of whoever
//! wrote the ISF.
//!
//! # Addresses are reached through owner structures, not stored inline
//!
//! Neither the local nor the remote address is a member of the endpoint. The
//! local address is reached through a `_LOCAL_ADDRESS` whose `pData` is a
//! pointer *to a pointer* to an `_IN_ADDR` on most builds and a pointer
//! *directly* to one in the Windows 10 UDP case, and the address family lives in
//! a separate `_INETAF`. Both IPv4 and IPv6 occur, in the same members, told
//! apart only by that family value. So the indirection depth is read out of the
//! symbol table's own pointer chain ([`decode::follow_to_struct`]) rather than
//! branched on by version, and an IPv6 address is never rendered as IPv4: the
//! four bytes at the front of an `_IN_ADDR` holding an IPv6 address are a
//! legal-looking dotted quad and a completely fabricated one.

use std::ops::Range;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::binding::BindError;
use seance_memory::object::{ObjError, PlausibilityFailure, StructReader};
use seance_memory::scan::{
    scan_layer, scan_range, MultiStringScanner, ScanConfig, ScanError, ScanOutcome,
};
use seance_memory::Incomplete;
use seance_symbols::{SymbolError, SymbolTable};

use crate::profile::{KernelBuild, WindowsProfile};

#[path = "netscan_decode.rs"]
pub mod decode;
#[path = "netscan_legacy.rs"]
pub mod legacy;
#[path = "netscan_netstat.rs"]
pub mod netstat;

pub use decode::{NetworkEndpoint, Protocol, SocketState, Timestamp};
pub use legacy::{legacy_netscan, LegacySymbols};
pub use netstat::{netstat, NetstatConfig, NetstatOutcome, TcpipModule};

/// Microsoft's `AF_INET`. Two, as everywhere.
pub const AF_INET: u64 = 2;

/// Microsoft's `AF_INET6`.
///
/// **23, not 30.** POSIX and BSD number `AF_INET6` 30, and Python's
/// `socket.AF_INET6` follows them; Windows numbers it 23. The value in the image
/// is Microsoft's, and reading it against the POSIX constant would classify
/// every IPv6 socket on the machine as an unknown family and drop it.
pub const AF_INET6: u64 = 23;

/// The `_POOL_HEADER` member holding the four-byte allocation tag.
const POOL_TAG_MEMBER: &str = "PoolTag";

/// Types this module reads, by the names Windows symbol tables give them.
const TYPE_TCP_ENDPOINT: &str = "_TCP_ENDPOINT";
const TYPE_TCP_LISTENER: &str = "_TCP_LISTENER";
const TYPE_UDP_ENDPOINT: &str = "_UDP_ENDPOINT";
const TYPE_INETAF: &str = "_INETAF";
const TYPE_ADDRINFO: &str = "_ADDRINFO";
const TYPE_IN_ADDR: &str = "_IN_ADDR";
const TYPE_POOL_HEADER: &str = "_POOL_HEADER";
const TYPE_EPROCESS: &str = "_EPROCESS";

/// Windows XP and Server 2003's bound-endpoint object, in tcpip.sys.
pub(crate) const TYPE_ADDRESS_OBJECT: &str = "_ADDRESS_OBJECT";
/// Windows XP and Server 2003's TCP connection block, in tcpip.sys.
pub(crate) const TYPE_TCPT_OBJECT: &str = "_TCPT_OBJECT";

/// First Windows *major* version whose tcpip.sys has the objects
/// [`NetworkSymbols`] decodes.
///
/// Vista rewrote the TCP/IP stack: `_TCP_ENDPOINT`, `_TCP_LISTENER`,
/// `_UDP_ENDPOINT`, `_INETAF` and the partition table are all its. Below this,
/// tcpip.sys has none of them and [`legacy`] decodes the objects it does have.
/// The two share no structure and not even the sense of `_POOL_HEADER.PoolType`,
/// which is why this is a fork in [`NetworkPlan`] and not a flag.
pub const FIRST_MODERN_TCPIP_MAJOR: u32 = 6;

/// First Windows build whose tcpip.sys additionally allocates TCP endpoints
/// under the `TTcb` tag.
///
/// Server 2022 (20348) introduced it and Windows 11 inherits it. An image at or
/// above this build swept without `TTcb` silently loses whichever endpoints
/// happened to be allocated under it — a short connection list that looks
/// complete.
pub const FIRST_TTCB_BUILD: u32 = 20348;

/// First Windows *major* version whose pool sweep runs in the kernel's virtual
/// address space rather than in physical memory.
///
/// Before Windows 10 these allocations are in non-paged physical memory and
/// sweeping the physical layer finds every one of them, including those the
/// virtual address space no longer maps. From Windows 10 the pool is laid out
/// such that the sweep is done against the kernel virtual layer instead, and
/// doing otherwise changes which objects are found.
pub const FIRST_VIRTUAL_SCAN_MAJOR: u32 = 10;

/// Ceiling on endpoints one sweep will return.
///
/// A busy server has a few thousand sockets. Reaching this means the sweep is
/// matching noise, not that the machine was busy, and it is reported as a cap
/// rather than as the end of the results.
pub const MAX_ENDPOINTS: usize = 200_000;

/// Ceiling on individually recorded rejected candidates.
///
/// The *count* of rejections stays exact past this point; only per-candidate
/// detail is dropped, because a pool-tag sweep of a large image produces
/// hundreds of thousands of four-byte coincidences and none of them is evidence.
pub const MAX_RECORDED_REJECTIONS: usize = 512;

/// How many pointer indirections a member may declare before the chain is
/// treated as a defect in the symbol table rather than as a layout.
///
/// The deepest real chain is `_LOCAL_ADDRESS.pData`, a pointer to a pointer to
/// an `_IN_ADDR`: two. Four leaves room for a build nobody has seen yet while
/// bounding a table that points at itself.
pub const MAX_POINTER_LEVELS: u32 = 4;

/// Everything that stops network-object analysis before it can produce a result
/// worth reading.
///
/// Note what is *not* here: a candidate that failed validation. That is an
/// answer about one four-byte coincidence in memory, and it lands in
/// [`NetscanOutcome::rejected`] where an examiner can count it.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// This Windows build's network objects cannot be decoded with what is
    /// available, and no partial answer would be honest.
    ///
    /// The message names exactly what is missing — a build predating the pool
    /// tags, a symbol table without `_TCP_ENDPOINT`, a member this build does
    /// not have — so an examiner can tell "we could not look" from "we looked
    /// and found nothing".
    #[error("network objects cannot be decoded on this build: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// The Windows build number was never established.
    ///
    /// Which pool tags exist, and which address space they live in, both depend
    /// on it. Guessing either produces a connection list that is wrong without
    /// being obviously wrong.
    #[error(
        "the Windows build number was never established, so neither the pool tags tcpip.sys uses \
         on this build nor the address space they live in can be chosen"
    )]
    BuildUnknown,

    /// The kernel symbol table and the tcpip symbol table describe machines of
    /// different pointer widths.
    ///
    /// One of them is not this image's. Reading `_TCP_ENDPOINT.Owner` as an
    /// eight-byte pointer in a four-byte address space yields an address in
    /// nobody's kernel, and the `_EPROCESS` read from it parses.
    #[error(
        "the kernel symbols declare {kernel}-byte pointers and the tcpip symbols declare \
         {network}-byte pointers, so one of the two tables does not describe this image"
    )]
    PointerWidthMismatch {
        /// Pointer width the kernel table declares.
        kernel: u64,
        /// Pointer width the network table declares.
        network: u64,
    },

    /// A typed read failed for a reason that invalidates the whole stage rather
    /// than one candidate.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The symbol table could not answer a question the stage depends on.
    #[error(transparent)]
    Symbols(#[from] SymbolError),

    /// The sweep itself could not be run.
    #[error("scanning for tcpip.sys's pool tags failed: {0}")]
    Scan(#[from] ScanError),

    /// A layout the walk cannot proceed without could not be bound to this
    /// build.
    ///
    /// `#[error(transparent)]` here is deliberate, and it is not the
    /// transparency that made the original defect undiagnosable: a
    /// [`BindError`] states the stage that stopped, every name that was tried
    /// and what stopping cost, where a bare [`SymbolError`] states only that
    /// some type was unknown.
    #[error(transparent)]
    Bind(#[from] BindError),
}

impl NetError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            NetError::Unsupported { .. } => "unsupported_build",
            NetError::BuildUnknown => "build_unknown",
            NetError::PointerWidthMismatch { .. } => "pointer_width_mismatch",
            NetError::Object(err) => err.class(),
            NetError::Symbols(_) => "symbols",
            NetError::Scan(_) => "scan",
            NetError::Bind(err) => err.class(),
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            NetError::Object(err) => err.incomplete_reason(),
            NetError::Scan(_) => IncompleteReason::ShortRead,
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be decoded" refusal.
    pub(crate) fn unsupported(detail: impl Into<String>) -> NetError {
        NetError::Unsupported {
            detail: detail.into(),
        }
    }
}

/// Which kind of network object a pool tag marks.
///
/// The three are not interchangeable, and conflating them is a reporting error
/// with legal weight: a `_TCP_LISTENER` is a service this machine *offered*,
/// while a `_TCP_ENDPOINT` is a conversation it actually *had*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// An established, closing or historical TCP connection: two addresses and
    /// two ports.
    TcpEndpoint,
    /// A socket bound and listening: one address, one port, no peer.
    TcpListener,
    /// A UDP socket. Connectionless, so no state and no peer.
    UdpEndpoint,
    /// Windows XP's `_ADDRESS_OBJECT`: a bound endpoint of any transport, which
    /// is a listener when its protocol member says TCP and a socket when it says
    /// UDP. One object type covers what Vista split across two pool tags, so the
    /// transport is read rather than implied by the tag.
    AddressObject,
    /// Windows XP's `_TCPT_OBJECT`: one TCP connection, both addresses and both
    /// ports inline. The pre-Vista equivalent of `_TCP_ENDPOINT`, with none of
    /// its members.
    TcptObject,
}

impl ObjectKind {
    /// The structure name this object is decoded as.
    pub fn type_name(self) -> &'static str {
        match self {
            ObjectKind::TcpEndpoint => TYPE_TCP_ENDPOINT,
            ObjectKind::TcpListener => TYPE_TCP_LISTENER,
            ObjectKind::UdpEndpoint => TYPE_UDP_ENDPOINT,
            ObjectKind::AddressObject => TYPE_ADDRESS_OBJECT,
            ObjectKind::TcptObject => TYPE_TCPT_OBJECT,
        }
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            ObjectKind::TcpEndpoint => "tcp_endpoint",
            ObjectKind::TcpListener => "tcp_listener",
            ObjectKind::UdpEndpoint => "udp_endpoint",
            ObjectKind::AddressObject => "address_object",
            ObjectKind::TcptObject => "tcpt_object",
        }
    }
}

/// One pool tag and the object it marks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolTag {
    /// The four ASCII bytes as they appear in memory.
    pub tag: &'static str,
    /// What an allocation carrying it contains.
    pub kind: ObjectKind,
}

/// Which address space a sweep ran against.
///
/// Recorded on the outcome because it changes what could have been found: a
/// physical sweep reaches allocations the virtual address space no longer maps,
/// and a virtual sweep reaches only what is mapped now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanSpace {
    /// The kernel's virtual address space.
    KernelVirtual,
    /// Raw physical memory.
    Physical,
}

impl ScanSpace {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            ScanSpace::KernelVirtual => "kernel_virtual",
            ScanSpace::Physical => "physical",
        }
    }
}

/// The symbol knowledge one image's network objects are decoded through.
///
/// Built once per image and checked once: every type and member the stage will
/// ever read is proved to exist here, so a build whose layout is unknown fails
/// at construction naming what is missing rather than at candidate three
/// thousand, having already emitted rows read at the wrong offsets.
///
/// # Where the types come from
///
/// tcpip.sys's structures are not in `ntoskrnl`'s PDB, so they are not in the
/// kernel symbol table discovery produces. A lab supplies them either as a
/// combined table or as a separate tcpip table ([`NetworkSymbols::with_table`],
/// reached in production by naming the ISF in `SEANCE_MEM_TCPIP_ISF`).
/// [`NetworkSymbols::from_profile`] tries the kernel table and refuses clearly
/// when it does not carry them — which is the common case, and is a missing
/// symbol pack rather than a defect. Saying so is more useful than an empty
/// result that reads as an idle machine.
#[derive(Debug, Clone)]
pub struct NetworkSymbols {
    /// Types for tcpip.sys's network objects.
    network: Arc<SymbolTable>,
    /// Types for the kernel: `_POOL_HEADER`, `_EPROCESS`, `_LIST_ENTRY`.
    kernel: Arc<SymbolTable>,
    /// Guest pointer width, from the tables themselves rather than from the
    /// machine running this.
    pointer_size: u64,
    /// Pool allocation granularity: 16 bytes on 64-bit Windows, 8 on 32-bit.
    pool_alignment: u64,
    /// Offset of `PoolTag` inside `_POOL_HEADER`, so a tag hit can be turned
    /// back into the start of the allocation.
    pool_tag_offset: u64,
    /// Size of `_POOL_HEADER`, so the allocation can be turned into the object
    /// that follows it.
    pool_header_size: u64,
    /// The tags this build actually uses.
    tags: Vec<PoolTag>,
    /// Which address space to sweep on this build.
    space: ScanSpace,
    /// Whether `network` came from a table the examiner supplied rather than
    /// from the one discovery matched to this image. Carried so the survey can
    /// declare it: nothing proved a supplied table describes this image's
    /// tcpip.sys, and rows read at its offsets must say so.
    network_supplied: bool,
}

impl NetworkSymbols {
    /// Resolve the network layout from the profile's own symbol table.
    ///
    /// # Errors
    ///
    /// [`NetError::Unsupported`] when this build predates the pool tags, or when
    /// the kernel symbol table does not carry tcpip.sys's types — which means a
    /// tcpip symbol pack is needed, not that the image has no network activity.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, NetError> {
        Self::resolve(profile, Arc::clone(&profile.symbols), false)
    }

    /// Resolve the network layout from a separate tcpip type table.
    ///
    /// `network` supplies `_TCP_ENDPOINT` and its neighbours; the profile's own
    /// table still supplies `_POOL_HEADER`, `_EPROCESS` and `_LIST_ENTRY`,
    /// because those are the kernel's and must come from the kernel's build.
    ///
    /// The supplied table's identity is the examiner's statement: discovery
    /// proves the kernel table against the kernel's own CodeView GUID and age,
    /// and nothing here can do the same for tcpip.sys. So the fact that it was
    /// supplied travels with the survey rather than being lost at this call.
    pub fn with_table(
        profile: &WindowsProfile,
        network: Arc<SymbolTable>,
    ) -> Result<Self, NetError> {
        Self::resolve(profile, network, true)
    }

    /// Whether tcpip.sys's types came from a table the examiner supplied.
    pub fn network_table_supplied(&self) -> bool {
        self.network_supplied
    }

    fn resolve(
        profile: &WindowsProfile,
        network: Arc<SymbolTable>,
        network_supplied: bool,
    ) -> Result<Self, NetError> {
        let build = require_supported_build(&profile.build)?;
        let kernel = Arc::clone(&profile.symbols);

        let network_pointer = network.pointer_size();
        let kernel_pointer = kernel.pointer_size();
        if network_pointer != kernel_pointer {
            return Err(NetError::PointerWidthMismatch {
                kernel: kernel_pointer,
                network: network_pointer,
            });
        }
        if network_pointer != 4 && network_pointer != 8 {
            return Err(NetError::unsupported(format!(
                "the symbol tables declare a pointer width of {network_pointer} byte(s), which is \
                 neither 4 nor 8 and so describes no addressable machine"
            )));
        }

        // Every member the stage will read, proved once. A build that names one
        // of these differently is a build this code has not been taught, and
        // saying so beats reading its bytes at somebody else's offsets.
        require(
            &network,
            TYPE_TCP_ENDPOINT,
            &[
                "InetAF",
                "AddrInfo",
                "State",
                "LocalPort",
                "RemotePort",
                "Owner",
                "CreateTime",
            ],
        )?;
        require(
            &network,
            TYPE_TCP_LISTENER,
            &["InetAF", "Owner", "CreateTime", "LocalAddr", "Port"],
        )?;
        require(
            &network,
            TYPE_UDP_ENDPOINT,
            &["InetAF", "Owner", "CreateTime", "LocalAddr", "Port"],
        )?;
        require(&network, TYPE_INETAF, &["AddressFamily"])?;
        require(&network, TYPE_ADDRINFO, &["Local", "Remote"])?;
        require(&network, TYPE_IN_ADDR, &["addr4", "addr6"])?;
        require(
            &kernel,
            TYPE_POOL_HEADER,
            &[POOL_TAG_MEMBER, "BlockSize", "PoolType"],
        )?;
        require(
            &kernel,
            TYPE_EPROCESS,
            &["UniqueProcessId", "ImageFileName"],
        )?;

        let pool_tag_offset = kernel.member_offset(TYPE_POOL_HEADER, POOL_TAG_MEMBER)?;
        let pool_header_size = kernel.size_of(TYPE_POOL_HEADER)?;
        if pool_header_size == 0 {
            return Err(NetError::unsupported(format!(
                "'{TYPE_POOL_HEADER}' declares a size of 0, so the object that follows an \
                 allocation header cannot be located"
            )));
        }

        let pool_alignment = if network_pointer == 8 { 16 } else { 8 };
        let space = if profile.build.major >= FIRST_VIRTUAL_SCAN_MAJOR {
            ScanSpace::KernelVirtual
        } else {
            ScanSpace::Physical
        };

        let mut tags = vec![
            PoolTag {
                tag: "TcpE",
                kind: ObjectKind::TcpEndpoint,
            },
            PoolTag {
                tag: "TcpL",
                kind: ObjectKind::TcpListener,
            },
            PoolTag {
                tag: "UdpA",
                kind: ObjectKind::UdpEndpoint,
            },
        ];
        if build >= FIRST_TTCB_BUILD && network_pointer == 8 {
            tags.push(PoolTag {
                tag: "TTcb",
                kind: ObjectKind::TcpEndpoint,
            });
        }

        Ok(NetworkSymbols {
            network,
            kernel,
            pointer_size: network_pointer,
            pool_alignment,
            pool_tag_offset,
            pool_header_size,
            tags,
            space,
            network_supplied,
        })
    }

    /// The tcpip type table.
    pub fn network_table(&self) -> &Arc<SymbolTable> {
        &self.network
    }

    /// The kernel type table.
    pub fn kernel_table(&self) -> &Arc<SymbolTable> {
        &self.kernel
    }

    /// Guest pointer width in bytes, taken from the symbol table rather than
    /// from the machine running this.
    pub fn pointer_size(&self) -> u64 {
        self.pointer_size
    }

    /// Pool allocation granularity for this architecture.
    pub fn pool_alignment(&self) -> u64 {
        self.pool_alignment
    }

    /// The pool tags this build's tcpip.sys uses.
    pub fn tags(&self) -> &[PoolTag] {
        &self.tags
    }

    /// Which address space [`netscan`] will sweep on this build.
    pub fn scan_space(&self) -> ScanSpace {
        self.space
    }
}

/// Refuse a build whose tcpip.sys predates these objects, and hand back its
/// build number.
///
/// Windows XP and Server 2003 are the case that matters: they *have* network
/// activity, they *have* a tcpip.sys, and they have neither these pool tags nor
/// these structures. Returning an empty result there would say "no network
/// activity" about a machine that may have been mid-exfiltration.
///
/// This refusal is still correct and still fires: what changed is that
/// [`NetworkPlan`] no longer routes those builds here at all. It sends them to
/// [`legacy`], which decodes the objects they do have. Reaching this arm now
/// means a caller asked the *modern* decoder for a pre-Vista image, and the
/// answer to that is unchanged.
fn require_supported_build(build: &KernelBuild) -> Result<u32, NetError> {
    let number = build.build.ok_or(NetError::BuildUnknown)?;
    if build.major < FIRST_MODERN_TCPIP_MAJOR {
        return Err(NetError::unsupported(format!(
            "Windows {}.{} (build {number}) predates the TcpE/TcpL/UdpA pool tags: its tcpip.sys \
             tracks connections in _ADDRESS_OBJECT and _TCPT_OBJECT structures, which this stage \
             does not decode. This is not an absence of network activity",
            build.major, build.minor
        )));
    }
    Ok(number)
}

/// Prove a type and its members exist before anything is read through them.
fn require(table: &SymbolTable, type_name: &str, members: &[&str]) -> Result<(), NetError> {
    if !table.has_type(type_name) {
        return Err(NetError::unsupported(format!(
            "the symbol table has no '{type_name}' type, so tcpip.sys's network objects cannot be \
             decoded on this build without a matching symbol pack"
        )));
    }
    for member in members {
        if !table.has_member(type_name, member) {
            return Err(NetError::unsupported(format!(
                "'{type_name}' in this build's symbol table has no '{member}' member, so that \
                 field cannot be read at any offset"
            )));
        }
    }
    Ok(())
}

/// How much of the address space to sweep, and what bounds the sweep.
#[derive(Debug, Clone)]
pub struct NetscanConfig {
    /// Chunking geometry and caps for the underlying scan.
    pub scan: ScanConfig,
    /// Restrict the sweep to one range of the scanned space. `None` sweeps every
    /// mapped byte, which is what finds objects nothing points at any more.
    pub range: Option<Range<u64>>,
    /// Ceiling on endpoints returned.
    pub max_endpoints: usize,
    /// Ceiling on individually recorded rejections.
    pub max_recorded_rejections: usize,
}

impl Default for NetscanConfig {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            range: None,
            max_endpoints: MAX_ENDPOINTS,
            max_recorded_rejections: MAX_RECORDED_REJECTIONS,
        }
    }
}

/// One tag match that did not survive validation.
///
/// Kept, and counted exactly, because the ratio of candidates to endpoints is
/// how an examiner judges whether a sweep was working: a sweep that rejected
/// everything and a sweep that found nothing to reject are different findings.
#[derive(Debug, Clone)]
pub struct Rejected {
    /// Where the candidate object would have started.
    pub address: u64,
    /// The tag that matched.
    pub tag: &'static str,
    /// Why it was not believed.
    pub reason: String,
}

/// Everything one sweep found, and everything it could not do.
#[derive(Debug, Clone)]
pub struct NetscanOutcome {
    /// Decoded endpoints, ascending by address. A dual-stack listener yields one
    /// row per address family, exactly as it is bound.
    pub endpoints: Vec<NetworkEndpoint>,
    /// Rejected candidates, capped by [`NetscanConfig::max_recorded_rejections`].
    pub rejected: Vec<Rejected>,
    /// How many candidates were rejected in total. Exact even when the list above
    /// was capped.
    pub rejected_total: usize,
    /// How many tag matches were examined.
    pub candidates: usize,
    /// Which address space was swept.
    pub space: ScanSpace,
    /// The part of that space the sweep covered, when it was bounded rather
    /// than swept whole. `None` means every address the layer has.
    ///
    /// On the record because a bounded sweep says nothing about the addresses
    /// outside its bound, and the scan's own unread list cannot say so: those
    /// addresses were never part of the walk.
    pub swept: Option<Range<u64>>,
    /// The underlying scan's own account of what it read and what it could not.
    pub scan: ScanOutcome,
    /// Whether the endpoint cap fired. The sweep stopped; the image did not run
    /// out of objects.
    pub truncated: bool,
    /// Everything a report must declare about this result.
    pub incomplete: Vec<Incomplete>,
}

impl NetscanOutcome {
    /// Whether every mapped byte was examined and every endpoint returned.
    ///
    /// The question a report must ask before writing "no network activity": an
    /// incomplete sweep that found nothing says nothing about the machine.
    pub fn is_complete(&self) -> bool {
        !self.truncated && self.scan.is_complete() && self.incomplete.is_empty()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "endpoints": self.endpoints.iter().map(|e| e.to_json()).collect::<Vec<_>>(),
            "endpoint_count": self.endpoints.len(),
            "candidates": self.candidates,
            "rejected_total": self.rejected_total,
            "rejected": self
                .rejected
                .iter()
                .map(|r| serde_json::json!({
                    "address": r.address,
                    "tag": r.tag,
                    "reason": r.reason,
                }))
                .collect::<Vec<_>>(),
            "space": self.space.as_str(),
            // Which addresses of that space were walked. `null` is the whole
            // layer; a range is a deliberate bound, and everything outside it
            // is a question this sweep did not ask.
            "swept": self.swept.as_ref().map(|range| serde_json::json!({
                "from": range.start,
                "to": range.end,
            })),
            "truncated": self.truncated,
            "complete": self.is_complete(),
            "scan": self.scan.to_json(),
            "incomplete": self.incomplete.iter().map(|i| i.to_json()).collect::<Vec<_>>(),
        })
    }
}

/// The three readers one network sweep needs, and why they are not one reader.
///
/// A pool candidate's *bytes* may live in physical memory while every pointer
/// inside it is a kernel virtual address, and the object's type comes from the
/// tcpip table while its owning process's type comes from the kernel's. Getting
/// either pairing wrong does not fail: each read returns bytes from an unrelated
/// address, and those bytes parse.
#[derive(Debug, Clone)]
pub(crate) struct Readers {
    /// Network objects: bytes in the swept space, pointers in kernel virtual.
    pub(crate) network: StructReader,
    /// Pool headers: the same two spaces, kernel types.
    pub(crate) pool: StructReader,
    /// The kernel's own address space, for `_EPROCESS` and `_LIST_ENTRY`.
    pub(crate) kernel: StructReader,
}

impl Readers {
    /// Build the readers for a sweep of `space`.
    pub(crate) fn new(
        profile: &WindowsProfile,
        symbols: &NetworkSymbols,
        space: ScanSpace,
    ) -> Readers {
        Readers::from_tables(
            profile,
            Arc::clone(&symbols.network),
            Arc::clone(&symbols.kernel),
            space,
        )
    }

    /// The same three readers from the two tables directly.
    ///
    /// [`legacy`] supplies a network table this crate declares rather than one
    /// discovery produced, and pairing the two spaces with the two tables is the
    /// part that must not be reimplemented per stage: a network object read
    /// through the kernel's table, or a pool header read in the wrong space,
    /// returns bytes from an unrelated address and those bytes parse.
    pub(crate) fn from_tables(
        profile: &WindowsProfile,
        network: Arc<SymbolTable>,
        kernel: Arc<SymbolTable>,
        space: ScanSpace,
    ) -> Readers {
        let swept = match space {
            ScanSpace::KernelVirtual => Arc::clone(&profile.kernel_space),
            ScanSpace::Physical => Arc::clone(&profile.physical),
        };
        let native = Arc::clone(&profile.kernel_space);
        Readers {
            network: StructReader::with_native(Arc::clone(&swept), Arc::clone(&native), network),
            pool: StructReader::with_native(swept, Arc::clone(&native), Arc::clone(&kernel)),
            kernel: StructReader::new(native, kernel),
        }
    }

    /// Readers that live entirely in the kernel's virtual address space, for the
    /// walk-based [`netstat`](netstat::netstat).
    pub(crate) fn virtual_only(profile: &WindowsProfile, symbols: &NetworkSymbols) -> Readers {
        Readers::new(profile, symbols, ScanSpace::KernelVirtual)
    }
}

/// Sweep memory for tcpip.sys's network objects.
///
/// # What an examiner learns
///
/// Every TCP connection, TCP listener and UDP socket whose pool allocation is
/// still in the image — including ones the kernel's own lists no longer
/// reference, which is the whole reason to sweep rather than walk. Each row
/// carries the owning process, the creation time and the connection state, so
/// "which process was talking to 203.0.113.7:443, and since when" is answerable.
///
/// # What a wrong answer looks like
///
/// A row with a plausible address and a plausible port read at another build's
/// offsets; a port of 20480 where the machine was serving on 80; an IPv6 address
/// rendered as its first four bytes in dotted-quad form. None of those looks
/// wrong in a report, which is why each is a refusal here rather than a best
/// effort.
///
/// # Errors
///
/// Only for failures that make the whole sweep meaningless: a build that cannot
/// be decoded, or a scan that could not be run. A candidate that failed
/// validation is not an error — it is a rejection, counted in
/// [`NetscanOutcome::rejected_total`].
pub fn netscan(
    profile: &WindowsProfile,
    symbols: &NetworkSymbols,
    config: &NetscanConfig,
) -> Result<NetscanOutcome, NetError> {
    let space = symbols.scan_space();
    let readers = Readers::new(profile, symbols, space);
    let layer = match space {
        ScanSpace::KernelVirtual => Arc::clone(&profile.kernel_space),
        ScanSpace::Physical => Arc::clone(&profile.physical),
    };

    let needles: Vec<&[u8]> = symbols.tags.iter().map(|t| t.tag.as_bytes()).collect();
    let scanner = MultiStringScanner::new("windows-network-pool-tags", needles)?;
    // A caller's own bound wins; otherwise a kernel-virtual sweep covers the
    // kernel half rather than starting at address zero. Starting at zero on
    // x86-64 does not merely waste the user half: the region enumeration stops
    // at the non-canonical gap between the halves, so the sweep never reaches
    // the kernel addresses where every pool allocation is and reports an empty
    // network. See [`crate::poolscan::kernel_half_sweep`].
    let swept = config.range.clone().or_else(|| match space {
        ScanSpace::KernelVirtual => crate::poolscan::kernel_half_start(symbols.pointer_size())
            .and_then(|floor| crate::poolscan::kernel_half_sweep(floor, layer.max_address())),
        ScanSpace::Physical => None,
    });
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
            // The scanner cannot report a pattern it was not given. Recording it
            // rather than ignoring it means a defect here is visible instead of
            // silently thinning the results.
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

        match examine(&readers, symbols, tag, hit.address) {
            Ok(mut rows) => endpoints.append(&mut rows),
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
            .then_with(|| a.protocol.as_str().cmp(b.protocol.as_str()))
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
        // What "not read" means depends on the space, and rendering the two
        // alike is the difference between a gap in the evidence and a part of
        // the address space that never held anything. See
        // [`crate::poolscan::unswept_detail`], which says the same of the pool
        // sweep this one is shaped after.
        let detail = match space {
            ScanSpace::Physical => format!(
                "{} byte(s) of the physical address space could not be swept, so an endpoint \
                 lying in them would not appear here",
                outcome.unread_bytes
            ),
            ScanSpace::KernelVirtual => format!(
                "{} byte(s) of the swept range of the kernel_virtual address space were not \
                 read. Most of a kernel address space translates nowhere and holds nothing to \
                 find; the rest is pages the acquisition did not capture, where an endpoint \
                 would not appear here. This sweep cannot tell the two apart, so the total is an \
                 upper bound on what was lost and not a measure of it",
                outcome.unread_bytes
            ),
        };
        incomplete.push(Incomplete::new(IncompleteReason::ShortRead, detail));
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

/// Record a rejection, keeping the list bounded without losing the count.
fn push_rejection(into: &mut Vec<Rejected>, cap: usize, rejection: Rejected) {
    if into.len() < cap {
        into.push(rejection);
    }
}

/// Turn one tag match into rows, or into the reason it is not one.
///
/// The order is deliberate: the cheap structural tests that reject a four-byte
/// coincidence run before anything is decoded, because decoding a coincidence is
/// how a plausible wrong row gets made.
fn examine(
    readers: &Readers,
    symbols: &NetworkSymbols,
    tag: PoolTag,
    tag_address: u64,
) -> Result<Vec<NetworkEndpoint>, String> {
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

    // Vista and later encode the pool type so that non-paged is even and
    // non-zero, and a freed block is zero; paged pool is odd. tcpip's network
    // objects are allocated non-paged, and a freed one is exactly the historical
    // connection this sweep exists to find, so both are admitted and paged pool
    // is not. Windows XP's encoding is the other way round, which is one more
    // reason this stage refuses XP outright rather than guessing.
    if pool_type % 2 != 0 {
        return Err(format!(
            "the allocation is paged pool (PoolType {pool_type}), and tcpip.sys's network objects \
             are allocated non-paged"
        ));
    }

    let type_name = tag.kind.type_name();
    let type_size = readers
        .network
        .size_of(type_name)
        .map_err(|err| format!("'{type_name}' has no declared size: {err}"))?
        .bytes();
    let allocation = block_size.saturating_mul(symbols.pool_alignment);
    if allocation < type_size {
        return Err(format!(
            "the allocation is {allocation} byte(s) and '{type_name}' is {type_size}, so the \
             object cannot fit in it"
        ));
    }

    // Structural plausibility. Alignment, containment and full backing are
    // rejections: without them nothing can be read at all. A pointer member
    // holding a non-canonical value is *recorded* rather than fatal, because a
    // freed allocation legitimately has scrubbed pointers and is still the
    // historical connection an examiner wants to see.
    let verdict = readers
        .network
        .check_struct_aligned(object_address, type_name, symbols.pool_alignment)
        .map_err(|err| {
            format!("'{type_name}' could not be checked at {object_address:#x}: {err}")
        })?;
    let mut notes = Vec::new();
    for failure in &verdict.failures {
        match failure {
            PlausibilityFailure::NonCanonicalPointer { member, value } => notes.push(format!(
                "'{member}' holds {value:#x}, which no canonical address space can contain"
            )),
            PlausibilityFailure::Unreadable { member, detail } => {
                notes.push(format!("'{member}' could not be read: {detail}"))
            }
            other => return Err(other.to_string()),
        }
    }

    decode::decode(readers, symbols, tag, object_address, notes)
}

// ── The orchestrated stage ──────────────────────────────────────────────────

/// Name of the driver whose partition table and port pools the walk reads.
pub const TCPIP_IMAGE_NAME: &str = "tcpip.sys";

/// Where tcpip.sys was found, and how.
#[derive(Debug, Clone)]
pub struct TcpipLocation {
    /// The driver's load address in kernel virtual space.
    pub base: u64,
    /// The loader entry it was read from, so the provenance can be checked.
    pub entry: u64,
    /// Whether the kernel module list the base came from was itself complete.
    /// A driver not found on a short list has not been shown to be absent.
    pub list_complete: bool,
}

impl TcpipLocation {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "base": self.base,
            "entry": self.entry,
            "module_list_complete": self.list_complete,
        })
    }
}

/// The sweep, the live walk, and the difference between them.
///
/// The difference is the finding. An endpoint the sweep found and the walk did
/// not is either historical — a connection torn down before acquisition — or
/// hidden, and an endpoint the walk reached and the sweep did not bounds how
/// much of memory the sweep actually saw.
#[derive(Debug, Clone)]
pub struct NetworkSurvey {
    /// The pool sweep. Always attempted; it is the half that needs nothing but
    /// the kernel's own symbols.
    pub scan: NetscanOutcome,
    /// The partition-table and port-pool walk, when tcpip.sys's own symbols
    /// permitted it.
    pub walk: Option<NetstatOutcome>,
    /// Why the walk did not run, when it did not.
    ///
    /// Most often a missing tcpip symbol pack, which is a fact about what the
    /// examiner has rather than about the machine. Never an empty walk in its
    /// place: an empty walk would make every swept endpoint look hidden.
    pub walk_unavailable: Option<String>,
    /// Where tcpip.sys was found, when it was.
    pub tcpip: Option<TcpipLocation>,
    /// Object addresses the sweep found and the walk did not reach.
    pub swept_only: Vec<u64>,
    /// Object addresses the walk reached and the sweep did not find.
    pub walked_only: Vec<u64>,
    /// Whether the two views can be subtracted at all.
    ///
    /// False when the walk did not run, when either half stopped early, or when
    /// the sweep ran in physical memory — where an object's address is a
    /// physical one and the walk's are kernel virtual, so the two sets are not
    /// addresses of the same kind and subtracting them would report every
    /// endpoint twice over as missing from the other view.
    pub comparable: bool,
    /// Why they can or cannot be subtracted.
    pub notes: Vec<String>,
    /// Which declared structure layout the rows were read at, and what it was
    /// confirmed against, when the layout was this crate's rather than a symbol
    /// table discovery matched to the image.
    ///
    /// `None` on a modern build, where every offset came from a vendor symbol
    /// table and the table's own provenance already travels with the profile.
    /// `Some` on Windows XP, because a report quoting those rows must be able to
    /// state where their offsets came from without reading this crate's source.
    pub layout: Option<String>,
}

impl NetworkSurvey {
    /// Whether both views ran in full and could be subtracted.
    ///
    /// The question a report must ask before writing "these were all the
    /// machine's connections" or "no socket was hidden".
    pub fn is_complete(&self) -> bool {
        self.scan.is_complete()
            && self.walk.as_ref().is_some_and(NetstatOutcome::is_complete)
            && self.comparable
    }

    /// Everything a report must declare about this survey.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = self.scan.incomplete.clone();
        match &self.walk {
            Some(walk) => out.extend(walk.incomplete.iter().cloned()),
            None => out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                self.walk_unavailable.clone().unwrap_or_else(|| {
                    "tcpip.sys's own tables were not walked, so no socket can be shown to be \
                     missing from them"
                        .to_string()
                }),
            )),
        }
        if !self.comparable {
            for note in &self.notes {
                out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    note.clone(),
                ));
            }
        }
        out
    }

    /// Serializable form for artifact metadata.
    ///
    /// A superset of [`NetscanOutcome::to_json`], so a consumer reading the
    /// sweep finds it where it has always been, with the walk and the
    /// difference beside it.
    ///
    /// `complete` is the **survey's** verdict, not the sweep's, and the sweep's
    /// own moves to `sweep_complete`. A consumer that reads one key to decide
    /// whether it may quote the record reads that key here; leaving the sweep's
    /// `true` in place would have it quote a one-view list as the machine's
    /// connections.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = self.scan.to_json();
        if let Some(object) = value.as_object_mut() {
            let sweep_complete = object
                .insert("complete".into(), serde_json::json!(self.is_complete()))
                .unwrap_or(serde_json::Value::Null);
            object.insert("sweep_complete".into(), sweep_complete);
            object.insert(
                "walk".into(),
                self.walk
                    .as_ref()
                    .map(NetstatOutcome::to_json)
                    .unwrap_or(serde_json::Value::Null),
            );
            object.insert(
                "walk_unavailable".into(),
                match &self.walk_unavailable {
                    Some(reason) => serde_json::json!(reason),
                    None => serde_json::Value::Null,
                },
            );
            object.insert(
                "tcpip".into(),
                self.tcpip
                    .as_ref()
                    .map(TcpipLocation::to_json)
                    .unwrap_or(serde_json::Value::Null),
            );
            object.insert(
                "layout".into(),
                match &self.layout {
                    Some(layout) => serde_json::json!(layout),
                    None => serde_json::Value::Null,
                },
            );
            object.insert("swept_only".into(), serde_json::json!(self.swept_only));
            object.insert("walked_only".into(), serde_json::json!(self.walked_only));
            object.insert("comparable".into(), serde_json::json!(self.comparable));
            object.insert("notes".into(), serde_json::json!(self.notes));
            object.insert(
                "survey_complete".into(),
                serde_json::json!(self.is_complete()),
            );
            object.insert(
                "incomplete".into(),
                serde_json::json!(self
                    .incomplete()
                    .iter()
                    .map(Incomplete::to_json)
                    .collect::<Vec<_>>()),
            );
        }
        value
    }
}

/// Find tcpip.sys's load address in the kernel's own module list.
///
/// The walk needs it because every symbol in `tcpip.pdb` is relative to the
/// image. Taking it from the loader entry rather than from a pool scan means
/// the answer has one stated provenance, and the list's own completeness
/// travels with it: a driver not found on a list that stopped early has not
/// been shown to be absent.
///
/// # Errors
///
/// [`NetError::Unsupported`] when the kernel module list cannot be walked, when
/// no entry names tcpip.sys, or when the entry that does has no readable base.
/// Each is a reason the live walk cannot run, and none of them is an empty
/// connection list.
pub fn locate_tcpip(profile: &WindowsProfile) -> Result<TcpipLocation, NetError> {
    let symbols = crate::modules::ModuleSymbols::from_profile(profile).map_err(|err| {
        NetError::unsupported(format!(
            "the kernel's loaded-module list cannot be described on this build, so tcpip.sys's \
             load address cannot be established: {err}"
        ))
    })?;
    let list = crate::modules::list_kernel_modules(
        profile,
        &symbols,
        &crate::modules::ModuleWalkConfig::default(),
    )
    .map_err(|err| {
        NetError::unsupported(format!(
            "the kernel's loaded-module list could not be walked, so tcpip.sys's load address \
             could not be established: {err}"
        ))
    })?;

    let found = list.modules.iter().find(|module| {
        module
            .base_name
            .name()
            .is_some_and(|name| name.eq_ignore_ascii_case(TCPIP_IMAGE_NAME))
    });
    let Some(module) = found else {
        return Err(NetError::unsupported(format!(
            "no entry in the kernel's loaded-module list is named {TCPIP_IMAGE_NAME}, so its \
             tables cannot be walked{}",
            if list.is_complete() {
                ""
            } else {
                " — and the list itself did not run to its end, so this is not evidence that the \
                 driver was not loaded"
            }
        )));
    };
    let Some(base) = module.base else {
        return Err(NetError::unsupported(format!(
            "the loaded-module entry for {TCPIP_IMAGE_NAME} at {:#x} has no readable base \
             address, so a symbol inside it cannot be located",
            module.entry
        )));
    };
    Ok(TcpipLocation {
        base,
        entry: module.entry,
        list_complete: list.is_complete(),
    })
}

/// Sweep for network objects, walk tcpip.sys's own tables, and subtract them —
/// the whole `network` stage.
///
/// This is the entry point an orchestrator calls. The sweep always runs; the
/// walk runs when tcpip.sys can be located and its symbols describe the tables.
/// Neither substitutes for the other, which is why a walk that could not run
/// leaves [`NetworkSurvey::walk`] empty and says so rather than letting the
/// sweep stand in for it.
///
/// # What an examiner learns
///
/// Every endpoint in memory, whether the kernel's own tables still reach it,
/// and — when both views ran in full — the difference in each direction.
/// [`NetworkSurvey::swept_only`] is the concealment list; a socket in it that
/// the machine had not closed was hidden from `netstat` and from every tool
/// built on the same tables.
///
/// # Errors
///
/// [`NetError`] only when the sweep itself is impossible: a build predating the
/// pool tags, or a symbol table without tcpip's types. A missing tcpip symbol
/// pack is **not** an error — the sweep still runs and
/// [`NetworkSurvey::walk_unavailable`] says what would be needed.
pub fn survey_network(
    profile: &WindowsProfile,
    symbols: &NetworkSymbols,
    config: &NetscanConfig,
    walk_config: &NetstatConfig,
) -> Result<NetworkSurvey, NetError> {
    let scan = netscan(profile, symbols, config)?;

    let (tcpip, walk, walk_unavailable) = match locate_tcpip(profile) {
        Err(err) => (None, None, Some(err.to_string())),
        Ok(location) => {
            let module = TcpipModule::new(location.base, Arc::clone(symbols.network_table()));
            match netstat(profile, symbols, &module, walk_config) {
                Ok(walk) => (Some(location), Some(walk), None),
                Err(err) => (
                    Some(location),
                    None,
                    Some(format!(
                        "tcpip.sys's partition table and port pools could not be walked, so this \
                         list is the sweep alone and no socket can be shown to be missing from the \
                         kernel's own tables: {err}"
                    )),
                ),
            }
        }
    };

    let mut survey = NetworkSurvey {
        scan,
        walk,
        walk_unavailable,
        tcpip,
        swept_only: Vec::new(),
        walked_only: Vec::new(),
        comparable: false,
        notes: Vec::new(),
        // A table discovery matched to the image needs no declaration here: its
        // provenance already travels with the profile. A table the examiner
        // supplied does, because nothing proved it describes this image's
        // tcpip.sys and a report quoting these rows has to be able to say so.
        layout: symbols
            .network_table_supplied()
            .then(|| SUPPLIED_TCPIP_LAYOUT.to_string()),
    };
    cross_reference(&mut survey);
    Ok(survey)
}

/// What a survey declares when tcpip.sys's types came from a table the examiner
/// supplied rather than from the one discovery matched to this image.
///
/// Discovery proves the kernel's symbols against the kernel's own CodeView GUID
/// and age, and refuses a near match. Nothing proves a supplied tcpip table:
/// which tcpip.pdb is right is decided by the driver build the image loaded,
/// and this crate does not read it. So the offsets these rows were taken at
/// rest on the examiner's statement, and the record says which it is instead of
/// letting them pass as matched symbols.
const SUPPLIED_TCPIP_LAYOUT: &str =
    "read at the layout declared by an examiner-supplied tcpip.sys symbol table \
     (SEANCE_MEM_TCPIP_ISF), which was not matched to this image's tcpip.sys by GUID and age";

/// Which of the two decoders this image's tcpip.sys needs.
///
/// The choice is made once, from the build, and nothing downstream re-decides
/// it. That matters more than it looks: the two families share a pool sweep and
/// a row type and share **no** structure, no member name and not even the sense
/// of `_POOL_HEADER.PoolType`. A stage that picked per candidate, or fell back
/// from one to the other, would read one family's objects at the other's offsets
/// on some path — and that failure produces a full table of plausible addresses,
/// ports and PIDs rather than an error.
#[derive(Debug, Clone)]
pub enum NetworkPlan {
    /// Windows Vista and later: the `TcpE`/`TcpL`/`UdpA` objects, plus the walk
    /// of tcpip.sys's partition table and port pools.
    Modern(NetworkSymbols),
    /// Windows XP: the `TCPA`/`TCPT` objects. See [`legacy`].
    Legacy(LegacySymbols),
}

impl NetworkPlan {
    /// Choose the decoder this image's build requires.
    ///
    /// # Errors
    ///
    /// [`NetError::BuildUnknown`] when no build number was established, and
    /// [`NetError::Unsupported`] when the chosen decoder has nothing that
    /// describes this build — a missing tcpip symbol pack on a modern image, a
    /// pre-Vista family with no confirmed layout on an old one. Each names what
    /// is missing, and none of them is an empty endpoint list.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, NetError> {
        Self::from_profile_with_tcpip(profile, None)
    }

    /// Choose the decoder, taking tcpip.sys's types from a table of their own.
    ///
    /// This is the only route by which a lab that fetched `tcpip.pdb` can use
    /// it. `_TCP_ENDPOINT` and its neighbours are not in `ntoskrnl`'s PDB, so
    /// on a modern build the profile's own table normally cannot describe them
    /// and the stage refuses by name — which is a fact about the symbol pack,
    /// not about the machine's network activity.
    ///
    /// `None` is the ordinary case and behaves exactly as it always has.
    ///
    /// A pre-Vista build ignores the table: Windows XP's tcpip.sys has none of
    /// these types, and [`legacy`] reads the objects it does have at layouts
    /// this crate states rather than from any symbol table. Refusing an XP
    /// image because a table it cannot use was supplied would cost the examiner
    /// the sweep that does work.
    pub fn from_profile_with_tcpip(
        profile: &WindowsProfile,
        tcpip: Option<Arc<SymbolTable>>,
    ) -> Result<Self, NetError> {
        if profile.build.major >= FIRST_MODERN_TCPIP_MAJOR {
            Ok(NetworkPlan::Modern(match tcpip {
                Some(network) => NetworkSymbols::with_table(profile, network)?,
                None => NetworkSymbols::from_profile(profile)?,
            }))
        } else {
            Ok(NetworkPlan::Legacy(LegacySymbols::from_profile(profile)?))
        }
    }

    /// Which address space the sweep will run against.
    pub fn scan_space(&self) -> ScanSpace {
        match self {
            NetworkPlan::Modern(symbols) => symbols.scan_space(),
            NetworkPlan::Legacy(symbols) => symbols.scan_space(),
        }
    }

    /// The pool tags this plan sweeps for.
    pub fn tags(&self) -> &[PoolTag] {
        match self {
            NetworkPlan::Modern(symbols) => symbols.tags(),
            NetworkPlan::Legacy(symbols) => symbols.tags(),
        }
    }
}

/// The whole `network` stage, for whichever tcpip.sys this image is running.
///
/// This is the entry point an orchestrator calls. On a modern build it is
/// [`survey_network`] unchanged: sweep, walk, subtract. On Windows XP it is the
/// sweep of [`legacy`] alone, and the walk is reported as unavailable with the
/// reason — never as an empty walk, which would make every swept endpoint look
/// hidden.
///
/// # Errors
///
/// [`NetError`] only when the sweep itself is impossible on this build.
pub fn survey_network_with(
    profile: &WindowsProfile,
    plan: &NetworkPlan,
    config: &NetscanConfig,
    walk_config: &NetstatConfig,
) -> Result<NetworkSurvey, NetError> {
    match plan {
        NetworkPlan::Modern(symbols) => survey_network(profile, symbols, config, walk_config),
        NetworkPlan::Legacy(symbols) => survey_legacy_network(profile, symbols, config),
    }
}

/// The pre-Vista survey: the sweep, and an honest account of the missing walk.
///
/// # Why there is no walk here
///
/// XP's live endpoint tables are `AddrObjTable` and `TCBTable`, two globals
/// *inside tcpip.sys*. Reaching either needs tcpip.sys's own symbols at its own
/// load address, and neither name is in any symbol table available to this
/// analysis: Microsoft's published XP `tcpip.pdb` files are public PDBs, which
/// carry no static globals and no type records. Locating them by scanning
/// tcpip.sys's data section for something that looks like a bucket array would
/// be a guess dressed as a walk, and its whole purpose is to be an independent
/// second view.
///
/// So the walk is absent and says so. [`NetworkSurvey::comparable`] stays false,
/// which is what stops a consumer subtracting one view from nothing and
/// reporting every endpoint as hidden.
fn survey_legacy_network(
    profile: &WindowsProfile,
    symbols: &LegacySymbols,
    config: &NetscanConfig,
) -> Result<NetworkSurvey, NetError> {
    let scan = legacy_netscan(profile, symbols, config)?;
    let layout = symbols.layout();

    let mut survey = NetworkSurvey {
        scan,
        walk: None,
        walk_unavailable: Some(format!(
            "this image is {}, whose live endpoint tables are the AddrObjTable and TCBTable \
             globals inside {TCPIP_IMAGE_NAME}. Neither name is in any symbol table available \
             here — the {TCPIP_IMAGE_NAME} PDBs Microsoft published for this family are public \
             PDBs, carrying neither static globals nor type records — so there is no second view \
             to compare the sweep against, and an endpoint the sweep found cannot be shown to \
             have been hidden from the kernel's own tables",
            layout.family
        )),
        // The sweep runs in physical memory and needs no module base, so
        // locating the driver would be recording a fact this stage did not use.
        tcpip: None,
        swept_only: Vec::new(),
        walked_only: Vec::new(),
        comparable: false,
        notes: Vec::new(),
        layout: Some(format!(
            "read at the {} layout, confirmed against {}",
            layout.family, layout.confirmed_against
        )),
    };
    cross_reference(&mut survey);
    Ok(survey)
}

/// Subtract the two views, or say why they cannot be subtracted.
///
/// Kept apart from [`survey_network`] so the rules are readable in one place:
/// each of them exists because ignoring it turns a limitation of the tool into
/// a page of findings about the suspect.
fn cross_reference(survey: &mut NetworkSurvey) {
    let Some(walk) = &survey.walk else {
        survey.notes.push(
            "only the pool sweep ran, so there is no second view to compare it against".to_string(),
        );
        return;
    };
    if survey.scan.space != ScanSpace::KernelVirtual {
        survey.notes.push(format!(
            "the sweep ran in {} memory and the walk in the kernel's virtual address space, so an \
             object's address means a different thing in each and the two views cannot be \
             subtracted",
            survey.scan.space.as_str()
        ));
        return;
    }

    let swept: std::collections::HashSet<u64> =
        survey.scan.endpoints.iter().map(|e| e.offset).collect();
    let walked: std::collections::HashSet<u64> = walk.endpoints.iter().map(|e| e.offset).collect();

    let mut swept_only: Vec<u64> = swept.difference(&walked).copied().collect();
    let mut walked_only: Vec<u64> = walked.difference(&swept).copied().collect();
    swept_only.sort_unstable();
    walked_only.sort_unstable();

    // Absence from an incomplete view is not evidence of concealment, so the
    // difference is reported and the claim is not.
    let mut comparable = true;
    if !walk.is_complete() {
        survey.notes.push(
            "the walk did not reach both halves of tcpip.sys's tables, so an endpoint absent from \
             it is not shown to have been hidden"
                .to_string(),
        );
        comparable = false;
    }
    if !survey.scan.is_complete() {
        survey.notes.push(
            "the sweep did not examine every mapped byte, so the endpoints it did not find are a \
             floor rather than a total"
                .to_string(),
        );
        comparable = false;
    }

    survey.swept_only = swept_only;
    survey.walked_only = walked_only;
    survey.comparable = comparable;
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_memory::{Architecture, MemoryLayer, PhysicalLayer};
    use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

    use crate::profile::{Evidence, Found, KernelBuild, WindowsProfile};

    /// Size of every synthetic image these tests build.
    pub(crate) const IMAGE_SIZE: usize = 0x4_0000;

    /// A hand-built image, written by address so a failing test points at one
    /// place rather than at a generator.
    pub(crate) struct Image {
        pub(crate) bytes: Vec<u8>,
    }

    impl Image {
        pub(crate) fn new() -> Self {
            Self {
                bytes: vec![0u8; IMAGE_SIZE],
            }
        }

        pub(crate) fn write(&mut self, address: u64, data: &[u8]) {
            let at = address as usize;
            self.bytes[at..at + data.len()].copy_from_slice(data);
        }

        pub(crate) fn put_u64(&mut self, address: u64, value: u64) {
            self.write(address, &value.to_le_bytes());
        }

        pub(crate) fn put_u32(&mut self, address: u64, value: u32) {
            self.write(address, &value.to_le_bytes());
        }

        pub(crate) fn put_u16(&mut self, address: u64, value: u16) {
            self.write(address, &value.to_le_bytes());
        }

        /// A port, as tcpip.sys stores it: network byte order.
        pub(crate) fn put_port(&mut self, address: u64, port: u16) {
            self.write(address, &port.to_be_bytes());
        }

        pub(crate) fn layer(self) -> Arc<dyn MemoryLayer> {
            let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(self.bytes));
            Arc::new(PhysicalLayer::raw(source).expect("a non-empty image"))
        }
    }

    /// Compile an ISF from its JSON text.
    pub(crate) fn table(json: &str) -> Arc<SymbolTable> {
        let source = seance_symbols::load_slice(json.as_bytes(), &DecompressLimits::default())
            .expect("readable ISF bytes");
        Arc::new(
            SymbolTable::compile_source(source, &CompileOptions::default())
                .expect("a valid synthetic ISF"),
        )
    }

    /// A profile over one layer, with the symbol table and build supplied.
    ///
    /// The kernel and physical layers are the same object, so a pointer value is
    /// also a physical address: it keeps the fixtures readable without hiding
    /// the space split, which the readers still model.
    pub(crate) fn profile(
        layer: Arc<dyn MemoryLayer>,
        symbols: Arc<SymbolTable>,
        major: u32,
        build: Option<u32>,
    ) -> WindowsProfile {
        WindowsProfile {
            kernel_space: Arc::clone(&layer),
            physical: layer,
            symbols,
            pagefiles: Vec::new(),
            dtb: Found::new(0x1000, Evidence::Confirmed),
            kernel_base: Found::new(0x1_0000, Evidence::Confirmed),
            kdbg: None,
            build: KernelBuild {
                pdb: "ntkrnlmp.pdb".into(),
                guid: "0".repeat(32),
                age: 1,
                build_lab: None,
                major,
                minor: 0,
                build,
                // Synthetic fixture: no structure stated the build number.
                build_source: None,
            },
            architecture: Architecture::X64,
        }
    }

    /// Offsets the synthetic 64-bit ISF declares.
    ///
    /// Stated as constants so a test writes a field at the same place the symbol
    /// table says it is, and a mistake in one shows up as a failure rather than
    /// as agreement.
    pub(crate) mod off {
        pub(crate) const POOL_HEADER_SIZE: u64 = 16;
        pub(crate) const POOL_BLOCK_SIZE: u64 = 2;
        pub(crate) const POOL_TYPE: u64 = 4;
        pub(crate) const POOL_TAG: u64 = 8;

        pub(crate) const EPROCESS_PID: u64 = 0;
        pub(crate) const EPROCESS_NAME: u64 = 8;

        pub(crate) const INETAF_FAMILY: u64 = 4;

        pub(crate) const LOCAL_ADDRESS_PDATA: u64 = 16;
        pub(crate) const LOCAL_ADDRESS_UDP_PDATA: u64 = 0;

        pub(crate) const ADDRINFO_LOCAL: u64 = 0;
        pub(crate) const ADDRINFO_REMOTE: u64 = 16;

        pub(crate) const TCPE_INETAF: u64 = 16;
        pub(crate) const TCPE_ADDRINFO: u64 = 24;
        pub(crate) const TCPE_LIST_ENTRY: u64 = 32;
        pub(crate) const TCPE_STATE: u64 = 48;
        pub(crate) const TCPE_LOCAL_PORT: u64 = 52;
        pub(crate) const TCPE_REMOTE_PORT: u64 = 54;
        pub(crate) const TCPE_OWNER: u64 = 64;
        pub(crate) const TCPE_CREATE_TIME: u64 = 72;

        pub(crate) const TCPL_INETAF: u64 = 8;
        pub(crate) const TCPL_OWNER: u64 = 16;
        pub(crate) const TCPL_CREATE_TIME: u64 = 24;
        pub(crate) const TCPL_LOCAL_ADDR: u64 = 32;
        pub(crate) const TCPL_PORT: u64 = 40;
        pub(crate) const TCPL_NEXT: u64 = 48;

        pub(crate) const UDPA_INETAF: u64 = 8;
        pub(crate) const UDPA_OWNER: u64 = 16;
        pub(crate) const UDPA_CREATE_TIME: u64 = 24;
        pub(crate) const UDPA_LOCAL_ADDR: u64 = 32;
        pub(crate) const UDPA_PORT: u64 = 40;

        pub(crate) const HASH_TABLE_SIZE: u64 = 0;
        pub(crate) const HASH_NUM_ENTRIES: u64 = 4;
        pub(crate) const HASH_DIRECTORY: u64 = 8;

        pub(crate) const PARTITION_ENDPOINTS: u64 = 8;

        pub(crate) const BITMAP_SIZE_OF_BITMAP: u64 = 0;
        pub(crate) const BITMAP_BUFFER: u64 = 8;

        pub(crate) const PORT_POOL_BITMAP: u64 = 8;
        pub(crate) const PORT_POOL_ASSIGNMENTS: u64 = 256;
        pub(crate) const PORT_ASSIGNMENT_BIG_POOL_BASE: u64 = 24;
        pub(crate) const PORT_ASSIGNMENT_ENTRY_STRIDE: u64 = 32;
        pub(crate) const PORT_ASSIGNMENT_ENTRY: u64 = 16;
    }

    /// A synthetic 64-bit Windows ISF carrying both the kernel types this stage
    /// needs and tcpip.sys's network types, at the offsets `off` states.
    ///
    /// `local_addr_udp` selects the Windows 10 `_UDP_ENDPOINT` shape, whose
    /// `pData` is a single pointer to an `_IN_ADDR` rather than a pointer to a
    /// pointer — the variant a version-branching decoder gets wrong.
    pub(crate) fn windows_network_isf(local_addr_udp: bool) -> String {
        let udp_local_type = if local_addr_udp {
            "_LOCAL_ADDRESS_WIN10_UDP"
        } else {
            "_LOCAL_ADDRESS"
        };
        format!(
            r#"{{
  "metadata": {{
    "format": "6.2.0",
    "producer": {{"name": "seance-test", "version": "1.0.0"}},
    "windows": {{"pdb": {{"GUID": "AA1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                         "database": "ntkrnlmp.pdb", "machine_type": 34404}}}}
  }},
  "base_types": {{
    "pointer": {{"size": 8, "signed": false, "kind": "int", "endian": "little"}},
    "long long": {{"size": 8, "signed": true, "kind": "int", "endian": "little"}},
    "unsigned long": {{"size": 4, "signed": false, "kind": "int", "endian": "little"}},
    "long": {{"size": 4, "signed": true, "kind": "int", "endian": "little"}},
    "unsigned short": {{"size": 2, "signed": false, "kind": "int", "endian": "little"}},
    "unsigned be short": {{"size": 2, "signed": false, "kind": "int", "endian": "big"}},
    "unsigned char": {{"size": 1, "signed": false, "kind": "int", "endian": "little"}}
  }},
  "user_types": {{
    "_POOL_HEADER": {{"size": 16, "kind": "struct", "fields": {{
      "BlockSize": {{"offset": 2, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "PoolType": {{"offset": 4, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "PoolTag": {{"offset": 8, "type": {{"kind": "base", "name": "unsigned long"}}}}
    }}}},
    "_LIST_ENTRY": {{"size": 16, "kind": "struct", "fields": {{
      "Flink": {{"offset": 0, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}},
      "Blink": {{"offset": 8, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}}
    }}}},
    "_EPROCESS": {{"size": 64, "kind": "struct", "fields": {{
      "UniqueProcessId": {{"offset": 0, "type": {{"kind": "pointer",
                           "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "ImageFileName": {{"offset": 8, "type": {{"kind": "array", "count": 15,
                         "subtype": {{"kind": "base", "name": "unsigned char"}}}}}}
    }}}},
    "_LARGE_INTEGER": {{"size": 8, "kind": "union", "fields": {{
      "QuadPart": {{"offset": 0, "type": {{"kind": "base", "name": "long long"}}}}
    }}}},
    "_RTL_BITMAP": {{"size": 16, "kind": "struct", "fields": {{
      "SizeOfBitMap": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "Buffer": {{"offset": 8, "type": {{"kind": "pointer",
                  "subtype": {{"kind": "base", "name": "unsigned char"}}}}}}
    }}}},
    "_RTL_DYNAMIC_HASH_TABLE": {{"size": 40, "kind": "struct", "fields": {{
      "TableSize": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "NumEntries": {{"offset": 4, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "Directory": {{"offset": 8, "type": {{"kind": "pointer",
                     "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}}
    }}}},
    "_IN_ADDR": {{"size": 16, "kind": "union", "fields": {{
      "addr4": {{"offset": 0, "type": {{"kind": "array", "count": 4,
                 "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "addr6": {{"offset": 0, "type": {{"kind": "array", "count": 16,
                 "subtype": {{"kind": "base", "name": "unsigned char"}}}}}}
    }}}},
    "_INETAF": {{"size": 8, "kind": "struct", "fields": {{
      "AddressFamily": {{"offset": 4, "type": {{"kind": "base", "name": "unsigned short"}}}}
    }}}},
    "_LOCAL_ADDRESS": {{"size": 24, "kind": "struct", "fields": {{
      "pData": {{"offset": 16, "type": {{"kind": "pointer", "subtype":
                 {{"kind": "pointer", "subtype": {{"kind": "struct", "name": "_IN_ADDR"}}}}}}}}
    }}}},
    "_LOCAL_ADDRESS_WIN10_UDP": {{"size": 8, "kind": "struct", "fields": {{
      "pData": {{"offset": 0, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "struct", "name": "_IN_ADDR"}}}}}}
    }}}},
    "_ADDRINFO": {{"size": 24, "kind": "struct", "fields": {{
      "Local": {{"offset": 0, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "struct", "name": "_LOCAL_ADDRESS"}}}}}},
      "Remote": {{"offset": 16, "type": {{"kind": "pointer",
                  "subtype": {{"kind": "struct", "name": "_IN_ADDR"}}}}}}
    }}}},
    "_TCP_ENDPOINT": {{"size": 128, "kind": "struct", "fields": {{
      "InetAF": {{"offset": 16, "type": {{"kind": "pointer",
                  "subtype": {{"kind": "struct", "name": "_INETAF"}}}}}},
      "AddrInfo": {{"offset": 24, "type": {{"kind": "pointer",
                    "subtype": {{"kind": "struct", "name": "_ADDRINFO"}}}}}},
      "ListEntry": {{"offset": 32, "type": {{"kind": "struct", "name": "_LIST_ENTRY"}}}},
      "State": {{"offset": 48, "type": {{"kind": "enum", "name": "TCPStateEnum"}}}},
      "LocalPort": {{"offset": 52, "type": {{"kind": "base", "name": "unsigned be short"}}}},
      "RemotePort": {{"offset": 54, "type": {{"kind": "base", "name": "unsigned be short"}}}},
      "Owner": {{"offset": 64, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "struct", "name": "_EPROCESS"}}}}}},
      "CreateTime": {{"offset": 72, "type": {{"kind": "union", "name": "_LARGE_INTEGER"}}}}
    }}}},
    "_TCP_LISTENER": {{"size": 96, "kind": "struct", "fields": {{
      "InetAF": {{"offset": 8, "type": {{"kind": "pointer",
                  "subtype": {{"kind": "struct", "name": "_INETAF"}}}}}},
      "Owner": {{"offset": 16, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "struct", "name": "_EPROCESS"}}}}}},
      "CreateTime": {{"offset": 24, "type": {{"kind": "union", "name": "_LARGE_INTEGER"}}}},
      "LocalAddr": {{"offset": 32, "type": {{"kind": "pointer",
                     "subtype": {{"kind": "struct", "name": "_LOCAL_ADDRESS"}}}}}},
      "Port": {{"offset": 40, "type": {{"kind": "base", "name": "unsigned be short"}}}},
      "Next": {{"offset": 48, "type": {{"kind": "pointer",
                "subtype": {{"kind": "struct", "name": "_TCP_LISTENER"}}}}}}
    }}}},
    "_UDP_ENDPOINT": {{"size": 96, "kind": "struct", "fields": {{
      "InetAF": {{"offset": 8, "type": {{"kind": "pointer",
                  "subtype": {{"kind": "struct", "name": "_INETAF"}}}}}},
      "Owner": {{"offset": 16, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "struct", "name": "_EPROCESS"}}}}}},
      "CreateTime": {{"offset": 24, "type": {{"kind": "union", "name": "_LARGE_INTEGER"}}}},
      "LocalAddr": {{"offset": 32, "type": {{"kind": "pointer",
                     "subtype": {{"kind": "struct", "name": "{udp_local_type}"}}}}}},
      "Port": {{"offset": 40, "type": {{"kind": "base", "name": "unsigned be short"}}}},
      "Next": {{"offset": 48, "type": {{"kind": "pointer",
                "subtype": {{"kind": "struct", "name": "_UDP_ENDPOINT"}}}}}}
    }}}},
    "_PARTITION": {{"size": 32, "kind": "struct", "fields": {{
      "Endpoints": {{"offset": 8, "type": {{"kind": "pointer",
                     "subtype": {{"kind": "struct", "name": "_RTL_DYNAMIC_HASH_TABLE"}}}}}}
    }}}},
    "_PARTITION_TABLE": {{"size": 32, "kind": "struct", "fields": {{
      "Partitions": {{"offset": 0, "type": {{"kind": "array", "count": 1,
                      "subtype": {{"kind": "struct", "name": "_PARTITION"}}}}}}
    }}}},
    "_PORT_ASSIGNMENT_ENTRY": {{"size": 32, "kind": "struct", "fields": {{
      "Entry": {{"offset": 16, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "base", "name": "unsigned char"}}}}}}
    }}}},
    "_PORT_ASSIGNMENT_LIST": {{"size": 8192, "kind": "struct", "fields": {{
      "Assignments": {{"offset": 0, "type": {{"kind": "array", "count": 256,
                       "subtype": {{"kind": "struct", "name": "_PORT_ASSIGNMENT_ENTRY"}}}}}}
    }}}},
    "_PORT_ASSIGNMENT": {{"size": 32, "kind": "struct", "fields": {{
      "InPaBigPoolBase": {{"offset": 24, "type": {{"kind": "pointer",
                           "subtype": {{"kind": "struct", "name": "_PORT_ASSIGNMENT_LIST"}}}}}}
    }}}},
    "_INET_PORT_POOL": {{"size": 2304, "kind": "struct", "fields": {{
      "PortBitMap": {{"offset": 8, "type": {{"kind": "struct", "name": "_RTL_BITMAP"}}}},
      "PortAssignments": {{"offset": 256, "type": {{"kind": "array", "count": 256,
                           "subtype": {{"kind": "pointer",
                           "subtype": {{"kind": "struct", "name": "_PORT_ASSIGNMENT"}}}}}}}}
    }}}},
    "_PROTOCOL_COMPARTMENT": {{"size": 16, "kind": "struct", "fields": {{
      "PortPool": {{"offset": 0, "type": {{"kind": "pointer",
                    "subtype": {{"kind": "struct", "name": "_INET_PORT_POOL"}}}}}}
    }}}},
    "_INET_COMPARTMENT": {{"size": 48, "kind": "struct", "fields": {{
      "ProtocolCompartment": {{"offset": 32, "type": {{"kind": "pointer",
                               "subtype": {{"kind": "struct",
                                            "name": "_PROTOCOL_COMPARTMENT"}}}}}}
    }}}},
    "_INET_COMPARTMENT_SET": {{"size": 384, "kind": "struct", "fields": {{
      "InetCompartment": {{"offset": 328, "type": {{"kind": "pointer",
                           "subtype": {{"kind": "struct", "name": "_INET_COMPARTMENT"}}}}}}
    }}}}
  }},
  "enums": {{
    "TCPStateEnum": {{"base": "long", "size": 4, "constants": {{
      "CLOSED": 0, "LISTENING": 1, "SYN_SENT": 2, "SYN_RCVD": 3, "ESTABLISHED": 4,
      "FIN_WAIT1": 5, "FIN_WAIT2": 6, "CLOSE_WAIT": 7, "CLOSING": 8, "LAST_ACK": 9,
      "TIME_WAIT": 12, "DELETE_TCB": 13
    }}}}
  }},
  "symbols": {{}}
}}"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    // Where the synthetic fixture puts things. Every allocation is 16-byte
    // aligned, as a real pool allocation is.
    const POOL_TCPE: u64 = 0x2000;
    const TCPE: u64 = POOL_TCPE + off::POOL_HEADER_SIZE;
    const POOL_TCPL: u64 = 0x3000;
    const TCPL: u64 = POOL_TCPL + off::POOL_HEADER_SIZE;
    const POOL_UDPA: u64 = 0x4000;
    const UDPA: u64 = POOL_UDPA + off::POOL_HEADER_SIZE;

    const INETAF_V4_AT: u64 = 0x5000;
    const INETAF_V6_AT: u64 = 0x5100;
    const ADDRINFO_AT: u64 = 0x6000;
    const LOCAL_ADDRESS_AT: u64 = 0x6100;
    const LOCAL_ADDRESS_PTR_AT: u64 = 0x6200;
    const IN_ADDR_LOCAL_AT: u64 = 0x6300;
    const IN_ADDR_REMOTE_AT: u64 = 0x6400;
    const EPROCESS_AT: u64 = 0x7000;

    /// 2021-06-01T00:00:00Z as a Windows FILETIME.
    const CREATE_TIME: u64 = 132_669_792_000_000_000;

    /// A pool header whose tag, block size and pool type are all as a real
    /// non-paged allocation's would be.
    fn pool_header(image: &mut Image, base: u64, tag: &[u8; 4], blocks: u16) {
        image.put_u16(base + off::POOL_BLOCK_SIZE, blocks);
        image.put_u16(base + off::POOL_TYPE, 2);
        image.write(base + off::POOL_TAG, tag);
    }

    fn families(image: &mut Image) {
        image.put_u16(INETAF_V4_AT + off::INETAF_FAMILY, AF_INET as u16);
        image.put_u16(INETAF_V6_AT + off::INETAF_FAMILY, AF_INET6 as u16);
    }

    fn inetaf_for(family: u64) -> u64 {
        if family == AF_INET6 {
            INETAF_V6_AT
        } else {
            INETAF_V4_AT
        }
    }

    fn eprocess(image: &mut Image, pid: u64, name: &[u8]) {
        image.put_u64(EPROCESS_AT + off::EPROCESS_PID, pid);
        image.write(EPROCESS_AT + off::EPROCESS_NAME, name);
    }

    /// Everything a `_TCP_ENDPOINT` needs, laid out by hand.
    fn tcp_endpoint_image(family: u64, state: u32) -> Image {
        let mut image = Image::new();
        pool_header(&mut image, POOL_TCPE, b"TcpE", 8);

        image.put_u64(TCPE + off::TCPE_INETAF, inetaf_for(family));
        image.put_u64(TCPE + off::TCPE_ADDRINFO, ADDRINFO_AT);
        image.put_u32(TCPE + off::TCPE_STATE, state);
        image.put_port(TCPE + off::TCPE_LOCAL_PORT, 80);
        image.put_port(TCPE + off::TCPE_REMOTE_PORT, 49_152);
        image.put_u64(TCPE + off::TCPE_OWNER, EPROCESS_AT);
        image.put_u64(TCPE + off::TCPE_CREATE_TIME, CREATE_TIME);

        image.put_u64(ADDRINFO_AT + off::ADDRINFO_LOCAL, LOCAL_ADDRESS_AT);
        image.put_u64(ADDRINFO_AT + off::ADDRINFO_REMOTE, IN_ADDR_REMOTE_AT);
        image.put_u64(
            LOCAL_ADDRESS_AT + off::LOCAL_ADDRESS_PDATA,
            LOCAL_ADDRESS_PTR_AT,
        );
        image.put_u64(LOCAL_ADDRESS_PTR_AT, IN_ADDR_LOCAL_AT);

        families(&mut image);
        eprocess(&mut image, 1234, b"svchost.exe");
        image
    }

    fn symbols_for(image: Image, udp_win10: bool) -> (WindowsProfile, NetworkSymbols) {
        let table = table(&windows_network_isf(udp_win10));
        let profile = profile(image.layer(), table, 10, Some(22000));
        let symbols = NetworkSymbols::from_profile(&profile).expect("a supported build");
        (profile, symbols)
    }

    fn sweep(profile: &WindowsProfile, symbols: &NetworkSymbols) -> NetscanOutcome {
        netscan(profile, symbols, &NetscanConfig::default()).expect("a runnable sweep")
    }

    #[test]
    fn a_tcp_endpoint_found_by_its_pool_tag_is_decoded_with_its_ports_in_host_order() {
        // The whole point: 80 is stored as the bytes 00 50, and reading those
        // little-endian gives 20480 — a legal-looking ephemeral port that would
        // survive review while being completely wrong.
        let mut image = tcp_endpoint_image(AF_INET, 4);
        image.write(IN_ADDR_LOCAL_AT, &[10, 0, 0, 5]);
        image.write(IN_ADDR_REMOTE_AT, &[203, 0, 113, 7]);
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);
        let row = &outcome.endpoints[0];
        assert_eq!(row.offset, TCPE);
        assert_eq!(row.protocol, Protocol::TcpV4);
        assert_eq!(row.local_address.as_deref(), Some("10.0.0.5"));
        assert_eq!(row.local_port, 80, "not 20480");
        assert_eq!(row.remote_address.as_deref(), Some("203.0.113.7"));
        assert_eq!(row.remote_port, Some(49_152));
        assert_eq!(row.owner_pid, Some(1234));
        assert_eq!(row.owner_process.as_deref(), Some("svchost.exe"));
        assert!(
            matches!(
                &row.state,
                SocketState::Tcp { value: 4, name } if name.as_deref() == Some("ESTABLISHED")
            ),
            "{:?}",
            row.state
        );
        assert!(row.created.is_some());
    }

    #[test]
    fn an_ipv6_endpoint_is_never_rendered_as_its_first_four_bytes_in_dotted_quad_form() {
        // 2001:db8::1 begins with the bytes 20 01 0d b8, which as IPv4 is
        // "32.1.13.184": a plausible public address the machine never touched.
        let mut image = tcp_endpoint_image(AF_INET6, 4);
        let local = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let remote = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ];
        image.write(IN_ADDR_LOCAL_AT, &local);
        image.write(IN_ADDR_REMOTE_AT, &remote);
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);
        let row = &outcome.endpoints[0];
        assert_eq!(row.protocol, Protocol::TcpV6);
        assert_eq!(row.local_address.as_deref(), Some("2001:db8::1"));
        assert_eq!(row.remote_address.as_deref(), Some("2001:db8::2"));
        assert!(!row.local_address.as_deref().unwrap().contains('.'));
    }

    #[test]
    fn a_listener_bound_to_one_address_reports_that_address_and_a_wildcard_peer() {
        let mut image = Image::new();
        pool_header(&mut image, POOL_TCPL, b"TcpL", 8);
        image.put_u64(TCPL + off::TCPL_INETAF, INETAF_V4_AT);
        image.put_u64(TCPL + off::TCPL_OWNER, EPROCESS_AT);
        image.put_u64(TCPL + off::TCPL_CREATE_TIME, CREATE_TIME);
        image.put_u64(TCPL + off::TCPL_LOCAL_ADDR, LOCAL_ADDRESS_AT);
        image.put_port(TCPL + off::TCPL_PORT, 445);
        image.put_u64(
            LOCAL_ADDRESS_AT + off::LOCAL_ADDRESS_PDATA,
            LOCAL_ADDRESS_PTR_AT,
        );
        image.put_u64(LOCAL_ADDRESS_PTR_AT, IN_ADDR_LOCAL_AT);
        image.write(IN_ADDR_LOCAL_AT, &[192, 168, 1, 10]);
        families(&mut image);
        eprocess(&mut image, 4, b"System");
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);
        let row = &outcome.endpoints[0];
        assert_eq!(row.protocol, Protocol::TcpV4);
        assert_eq!(row.local_address.as_deref(), Some("192.168.1.10"));
        assert_eq!(row.local_port, 445);
        assert_eq!(row.remote_address.as_deref(), Some("0.0.0.0"));
        assert_eq!(row.remote_port, Some(0));
        assert_eq!(row.state, SocketState::Listening);
        assert_eq!(row.owner_pid, Some(4));
    }

    #[test]
    fn a_dual_stack_listener_with_no_bound_address_is_reported_on_both_families() {
        // A socket bound to nothing on an AF_INET6 listener accepts both IPv4
        // and IPv6 on Windows. Reporting one row would understate what the
        // machine was reachable on.
        let mut image = Image::new();
        pool_header(&mut image, POOL_TCPL, b"TcpL", 8);
        image.put_u64(TCPL + off::TCPL_INETAF, INETAF_V6_AT);
        image.put_u64(TCPL + off::TCPL_OWNER, EPROCESS_AT);
        image.put_u64(TCPL + off::TCPL_CREATE_TIME, CREATE_TIME);
        // LocalAddr stays null: the socket is bound to every address.
        image.put_port(TCPL + off::TCPL_PORT, 3389);
        families(&mut image);
        eprocess(&mut image, 900, b"TermService");
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert_eq!(outcome.endpoints.len(), 2, "{:?}", outcome.endpoints);
        let protocols: Vec<Protocol> = outcome.endpoints.iter().map(|e| e.protocol).collect();
        assert!(protocols.contains(&Protocol::TcpV4));
        assert!(protocols.contains(&Protocol::TcpV6));
        for row in &outcome.endpoints {
            assert_eq!(row.local_port, 3389);
            assert_eq!(row.state, SocketState::Listening);
        }
        let v6 = outcome
            .endpoints
            .iter()
            .find(|e| e.protocol == Protocol::TcpV6)
            .expect("the v6 row");
        assert_eq!(v6.local_address.as_deref(), Some("::"));
        assert_eq!(v6.remote_address.as_deref(), Some("::"));
        let v4 = outcome
            .endpoints
            .iter()
            .find(|e| e.protocol == Protocol::TcpV4)
            .expect("the v4 row");
        assert_eq!(v4.local_address.as_deref(), Some("0.0.0.0"));
    }

    #[test]
    fn a_udp_endpoint_has_no_state_and_no_peer_and_is_never_given_a_tcp_one() {
        let mut image = Image::new();
        pool_header(&mut image, POOL_UDPA, b"UdpA", 8);
        image.put_u64(UDPA + off::UDPA_INETAF, INETAF_V4_AT);
        image.put_u64(UDPA + off::UDPA_OWNER, EPROCESS_AT);
        image.put_u64(UDPA + off::UDPA_CREATE_TIME, CREATE_TIME);
        image.put_u64(UDPA + off::UDPA_LOCAL_ADDR, LOCAL_ADDRESS_AT);
        image.put_port(UDPA + off::UDPA_PORT, 53);
        image.put_u64(
            LOCAL_ADDRESS_AT + off::LOCAL_ADDRESS_PDATA,
            LOCAL_ADDRESS_PTR_AT,
        );
        image.put_u64(LOCAL_ADDRESS_PTR_AT, IN_ADDR_LOCAL_AT);
        image.write(IN_ADDR_LOCAL_AT, &[127, 0, 0, 1]);
        families(&mut image);
        eprocess(&mut image, 2000, b"dns.exe");
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);
        let row = &outcome.endpoints[0];
        assert_eq!(row.protocol, Protocol::UdpV4);
        assert_eq!(row.local_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(row.local_port, 53);
        assert_eq!(
            row.remote_address, None,
            "UDP is connectionless; a peer column would be an invention"
        );
        assert_eq!(row.remote_port, None);
        assert_eq!(row.state, SocketState::NotApplicable);
    }

    #[test]
    fn the_windows_ten_udp_local_address_shape_decodes_to_the_same_address() {
        // `_LOCAL_ADDRESS_WIN10_UDP.pData` is one pointer where `_LOCAL_ADDRESS`
        // has two. A decoder branching on version rather than on the symbol
        // table's own pointer chain reads an address out of whatever the
        // `_IN_ADDR`'s first eight bytes happen to be.
        let mut image = Image::new();
        pool_header(&mut image, POOL_UDPA, b"UdpA", 8);
        image.put_u64(UDPA + off::UDPA_INETAF, INETAF_V4_AT);
        image.put_u64(UDPA + off::UDPA_OWNER, EPROCESS_AT);
        image.put_u64(UDPA + off::UDPA_CREATE_TIME, CREATE_TIME);
        image.put_u64(UDPA + off::UDPA_LOCAL_ADDR, LOCAL_ADDRESS_AT);
        image.put_port(UDPA + off::UDPA_PORT, 5353);
        // One level of indirection only.
        image.put_u64(
            LOCAL_ADDRESS_AT + off::LOCAL_ADDRESS_UDP_PDATA,
            IN_ADDR_LOCAL_AT,
        );
        image.write(IN_ADDR_LOCAL_AT, &[224, 0, 0, 251]);
        families(&mut image);
        eprocess(&mut image, 77, b"mdns.exe");
        let (profile, symbols) = symbols_for(image, true);

        let outcome = sweep(&profile, &symbols);
        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);
        assert_eq!(
            outcome.endpoints[0].local_address.as_deref(),
            Some("224.0.0.251")
        );
        assert_eq!(outcome.endpoints[0].local_port, 5353);
    }

    #[test]
    fn windows_xp_is_refused_by_name_rather_than_reported_as_having_no_network_activity() {
        // The single most dangerous possible output of this stage: an empty
        // table a reader takes as evidence the machine was not networked.
        let image = tcp_endpoint_image(AF_INET, 4);
        let table = table(&windows_network_isf(false));
        let profile = profile(image.layer(), table, 5, Some(2600));
        let err = NetworkSymbols::from_profile(&profile)
            .expect_err("XP has no such pool tags and must not produce an empty result");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("predates"), "{err}");
        assert!(
            err.to_string()
                .contains("not an absence of network activity"),
            "{err}"
        );
    }

    #[test]
    fn a_build_number_that_was_never_established_is_refused_rather_than_assumed() {
        let image = tcp_endpoint_image(AF_INET, 4);
        let table = table(&windows_network_isf(false));
        let profile = profile(image.layer(), table, 10, None);
        let err = NetworkSymbols::from_profile(&profile)
            .expect_err("the tag set depends on the build number");
        assert_eq!(err.class(), "build_unknown");
    }

    #[test]
    fn a_symbol_table_without_tcpips_types_says_so_instead_of_returning_nothing() {
        let image = tcp_endpoint_image(AF_INET, 4);
        let json = windows_network_isf(false).replace("\"_TCP_ENDPOINT\"", "\"_NOT_TCP_ENDPOINT\"");
        let table = table(&json);
        let profile = profile(image.layer(), table, 10, Some(22000));
        let err = NetworkSymbols::from_profile(&profile).expect_err("no _TCP_ENDPOINT type");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("_TCP_ENDPOINT"), "{err}");
    }

    #[test]
    fn a_member_this_build_does_not_have_is_named_rather_than_read_at_offset_zero() {
        let image = tcp_endpoint_image(AF_INET, 4);
        let json = windows_network_isf(false).replace("\"RemotePort\"", "\"RemotePortRenamed\"");
        let table = table(&json);
        let profile = profile(image.layer(), table, 10, Some(22000));
        let err = NetworkSymbols::from_profile(&profile).expect_err("RemotePort is gone");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("RemotePort"), "{err}");
    }

    #[test]
    fn the_ttcb_tag_is_swept_on_builds_that_use_it_and_not_on_builds_that_do_not() {
        let table = table(&windows_network_isf(false));

        let modern = profile(Image::new().layer(), Arc::clone(&table), 10, Some(22000));
        let modern = NetworkSymbols::from_profile(&modern).expect("Windows 11");
        assert!(modern.tags().iter().any(|t| t.tag == "TTcb"));
        assert_eq!(modern.scan_space(), ScanSpace::KernelVirtual);

        let older = profile(Image::new().layer(), table, 6, Some(7601));
        let older = NetworkSymbols::from_profile(&older).expect("Windows 7");
        assert!(
            !older.tags().iter().any(|t| t.tag == "TTcb"),
            "Windows 7's tcpip.sys does not allocate under TTcb"
        );
        assert_eq!(older.scan_space(), ScanSpace::Physical);
    }

    #[test]
    fn a_ttcb_tagged_allocation_is_decoded_as_a_tcp_endpoint() {
        let mut image = tcp_endpoint_image(AF_INET, 4);
        image.write(POOL_TCPE + off::POOL_TAG, b"TTcb");
        image.write(IN_ADDR_LOCAL_AT, &[10, 0, 0, 5]);
        image.write(IN_ADDR_REMOTE_AT, &[203, 0, 113, 7]);
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);
        assert_eq!(outcome.endpoints[0].tag, "TTcb");
        assert_eq!(outcome.endpoints[0].protocol, Protocol::TcpV4);
    }

    #[test]
    fn an_allocation_too_small_to_hold_the_structure_is_rejected_with_that_reason() {
        let mut image = tcp_endpoint_image(AF_INET, 4);
        // One 16-byte block cannot hold a 128-byte endpoint.
        image.put_u16(POOL_TCPE + off::POOL_BLOCK_SIZE, 1);
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert!(outcome.endpoints.is_empty());
        assert_eq!(outcome.rejected_total, 1);
        assert!(
            outcome.rejected[0].reason.contains("cannot fit"),
            "{:?}",
            outcome.rejected
        );
    }

    #[test]
    fn a_paged_pool_allocation_is_rejected_because_tcpip_allocates_non_paged() {
        let mut image = tcp_endpoint_image(AF_INET, 4);
        image.put_u16(POOL_TCPE + off::POOL_TYPE, 3);
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert!(outcome.endpoints.is_empty());
        assert_eq!(outcome.rejected_total, 1);
        assert!(
            outcome.rejected[0].reason.contains("paged pool"),
            "{:?}",
            outcome.rejected
        );
    }

    #[test]
    fn a_freed_allocation_is_kept_because_a_closed_connection_is_the_point_of_sweeping() {
        let mut image = tcp_endpoint_image(AF_INET, 4);
        image.write(IN_ADDR_LOCAL_AT, &[10, 0, 0, 5]);
        image.write(IN_ADDR_REMOTE_AT, &[203, 0, 113, 7]);
        // PoolType 0 is a freed block.
        image.put_u16(POOL_TCPE + off::POOL_TYPE, 0);
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);
    }

    #[test]
    fn an_address_family_windows_never_uses_rejects_the_candidate() {
        // Four bytes matching "TcpE" inside unrelated data is common; the family
        // check is what stops one becoming a row.
        let mut image = tcp_endpoint_image(AF_INET, 4);
        image.put_u16(INETAF_V4_AT + off::INETAF_FAMILY, 0x99);
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert!(outcome.endpoints.is_empty());
        assert_eq!(outcome.rejected_total, 1);
        assert!(
            outcome.rejected[0].reason.contains("address family"),
            "{:?}",
            outcome.rejected
        );
    }

    #[test]
    fn a_tcp_state_the_enumeration_does_not_define_rejects_the_candidate() {
        let mut image = tcp_endpoint_image(AF_INET, 47);
        image.write(IN_ADDR_LOCAL_AT, &[10, 0, 0, 5]);
        image.write(IN_ADDR_REMOTE_AT, &[203, 0, 113, 7]);
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert!(outcome.endpoints.is_empty());
        assert_eq!(outcome.rejected_total, 1);
        assert!(
            outcome.rejected[0].reason.contains("47"),
            "{:?}",
            outcome.rejected
        );
    }

    #[test]
    fn a_creation_time_outside_any_believable_range_is_omitted_and_declared() {
        // 1601 is what an unwritten FILETIME reads as. Printing it would put a
        // date in the case record the machine never held.
        let mut image = tcp_endpoint_image(AF_INET, 4);
        image.write(IN_ADDR_LOCAL_AT, &[10, 0, 0, 5]);
        image.write(IN_ADDR_REMOTE_AT, &[203, 0, 113, 7]);
        image.put_u64(TCPE + off::TCPE_CREATE_TIME, 1);
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);
        let row = &outcome.endpoints[0];
        assert!(row.created.is_none());
        assert!(
            row.notes.iter().any(|n| n.contains("creation time")),
            "{:?}",
            row.notes
        );
    }

    #[test]
    fn a_null_owner_leaves_the_process_columns_empty_rather_than_guessed() {
        let mut image = tcp_endpoint_image(AF_INET, 4);
        image.write(IN_ADDR_LOCAL_AT, &[10, 0, 0, 5]);
        image.write(IN_ADDR_REMOTE_AT, &[203, 0, 113, 7]);
        image.put_u64(TCPE + off::TCPE_OWNER, 0);
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);
        let row = &outcome.endpoints[0];
        assert_eq!(row.owner_pid, None);
        assert_eq!(row.owner_process, None);
        assert!(
            row.notes.iter().any(|n| n.contains("Owner")),
            "{:?}",
            row.notes
        );
    }

    #[test]
    fn the_outcome_states_what_it_swept_and_what_it_could_not() {
        let mut image = tcp_endpoint_image(AF_INET, 4);
        image.write(IN_ADDR_LOCAL_AT, &[10, 0, 0, 5]);
        image.write(IN_ADDR_REMOTE_AT, &[203, 0, 113, 7]);
        let (profile, symbols) = symbols_for(image, false);

        let outcome = sweep(&profile, &symbols);
        assert_eq!(outcome.space, ScanSpace::KernelVirtual);
        assert!(outcome.candidates >= 1);
        assert!(outcome.is_complete(), "{:?}", outcome.incomplete);
        let json = outcome.to_json();
        assert_eq!(json["endpoint_count"], 1);
        assert_eq!(json["space"], "kernel_virtual");
        assert_eq!(json["complete"], true);
    }

    #[test]
    fn the_endpoint_cap_stops_the_sweep_and_is_never_mistaken_for_the_end_of_the_evidence() {
        let mut image = tcp_endpoint_image(AF_INET, 4);
        image.write(IN_ADDR_LOCAL_AT, &[10, 0, 0, 5]);
        image.write(IN_ADDR_REMOTE_AT, &[203, 0, 113, 7]);
        // A second, identical allocation elsewhere in the image.
        pool_header(&mut image, 0x8000, b"TcpE", 8);
        let second = 0x8000 + off::POOL_HEADER_SIZE;
        image.put_u64(second + off::TCPE_INETAF, INETAF_V4_AT);
        image.put_u64(second + off::TCPE_ADDRINFO, ADDRINFO_AT);
        image.put_u32(second + off::TCPE_STATE, 4);
        image.put_port(second + off::TCPE_LOCAL_PORT, 443);
        image.put_u64(second + off::TCPE_OWNER, EPROCESS_AT);
        image.put_u64(second + off::TCPE_CREATE_TIME, CREATE_TIME);
        let (profile, symbols) = symbols_for(image, false);

        let config = NetscanConfig {
            max_endpoints: 1,
            ..NetscanConfig::default()
        };
        let outcome = netscan(&profile, &symbols, &config).expect("a runnable sweep");
        assert_eq!(outcome.endpoints.len(), 1);
        assert!(outcome.truncated);
        assert!(!outcome.is_complete());
        assert!(outcome
            .incomplete
            .iter()
            .any(|i| i.detail.contains("cap of 1 endpoints")));
    }

    #[test]
    fn tables_that_disagree_about_pointer_width_are_refused_before_anything_is_read() {
        let image = tcp_endpoint_image(AF_INET, 4);
        let kernel = table(&windows_network_isf(false));
        let profile = profile(image.layer(), kernel, 10, Some(22000));
        // A genuinely coherent 32-bit table: its machine type has to agree with
        // its pointer width or the symbol crate refuses it before this code
        // sees it, which would test the wrong thing.
        let thirty_two = windows_network_isf(false)
            .replace(r#""pointer": {"size": 8"#, r#""pointer": {"size": 4"#)
            .replace(r#""machine_type": 34404"#, r#""machine_type": 332"#);
        let network = table(&thirty_two);
        let err = NetworkSymbols::with_table(&profile, network)
            .expect_err("one of the two tables is not this image's");
        assert_eq!(err.class(), "pointer_width_mismatch");
    }

    #[test]
    fn a_separately_supplied_tcpip_table_is_what_lets_the_network_stage_run_at_all() {
        // The kernel's PDB does not describe tcpip.sys, so the symbol table
        // discovery matched to the image cannot answer for `_TCP_ENDPOINT`.
        // Until a plan could be handed a second table, a lab that had fetched
        // tcpip.pdb still had no supported way to supply it, and every such
        // image reported no network surface whatever the lab had collected.
        let image = tcp_endpoint_image(AF_INET, 4);
        let kernel_only =
            windows_network_isf(false).replace("\"_TCP_ENDPOINT\"", "\"_NOT_TCP_ENDPOINT\"");
        let profile = profile(image.layer(), table(&kernel_only), 10, Some(22000));

        let refused = NetworkPlan::from_profile_with_tcpip(&profile, None)
            .expect_err("the kernel table carries no _TCP_ENDPOINT");
        assert_eq!(refused.class(), "unsupported_build");
        assert!(refused.to_string().contains("_TCP_ENDPOINT"), "{refused}");

        let tcpip = table(&windows_network_isf(false));
        let plan = NetworkPlan::from_profile_with_tcpip(&profile, Some(tcpip))
            .expect("a supplied tcpip table describes the network objects");
        let NetworkPlan::Modern(symbols) = plan else {
            panic!("a Windows 10 image takes the modern decoder");
        };
        assert!(symbols.network_table_supplied());
    }

    #[test]
    fn rows_read_through_a_supplied_tcpip_table_declare_where_their_layout_came_from() {
        // Discovery proves the kernel's symbols against the kernel's own GUID
        // and age. Nothing proves a supplied tcpip table — which tcpip.pdb is
        // right is decided by the driver build the image loaded — so a report
        // quoting these ports and PIDs has to be able to say the offsets rest
        // on the examiner's statement.
        let mut image = tcp_endpoint_image(AF_INET, 4);
        image.write(IN_ADDR_LOCAL_AT, &[10, 0, 0, 5]);
        image.write(IN_ADDR_REMOTE_AT, &[203, 0, 113, 7]);
        let kernel_only =
            windows_network_isf(false).replace("\"_TCP_ENDPOINT\"", "\"_NOT_TCP_ENDPOINT\"");
        let profile = profile(image.layer(), table(&kernel_only), 10, Some(22000));
        let symbols = NetworkSymbols::with_table(&profile, table(&windows_network_isf(false)))
            .expect("a supplied tcpip table");

        let survey = survey_network(
            &profile,
            &symbols,
            &NetscanConfig::default(),
            &NetstatConfig::default(),
        )
        .expect("the sweep half always runs");
        let json = survey.to_json();
        let layout = survey
            .layout
            .as_deref()
            .expect("a supplied table's provenance is on the record");
        assert!(layout.contains("SEANCE_MEM_TCPIP_ISF"), "{layout}");
        assert_eq!(json["layout"], serde_json::json!(layout));

        // The profile's own table declares nothing extra: its provenance
        // already travels with the profile.
        let (matched_profile, matched_symbols) = symbols_for(tcp_endpoint_image(AF_INET, 4), false);
        let matched = survey_network(
            &matched_profile,
            &matched_symbols,
            &NetscanConfig::default(),
            &NetstatConfig::default(),
        )
        .expect("the sweep half always runs");
        assert_eq!(matched.layout, None);
    }

    #[test]
    fn every_error_names_a_class_and_an_incomplete_reason() {
        // A failure with neither becomes a silently missing section of a report.
        let cases = [
            NetError::unsupported("no such type"),
            NetError::BuildUnknown,
            NetError::PointerWidthMismatch {
                kernel: 8,
                network: 4,
            },
        ];
        for case in cases {
            assert!(!case.class().is_empty());
            assert!(!case.to_incomplete().detail.is_empty());
            assert_eq!(
                case.incomplete_reason(),
                IncompleteReason::UnresolvedStructure
            );
        }
    }

    #[test]
    fn object_kinds_and_spaces_carry_stable_identifiers() {
        assert_eq!(ObjectKind::TcpEndpoint.type_name(), "_TCP_ENDPOINT");
        assert_eq!(ObjectKind::TcpListener.type_name(), "_TCP_LISTENER");
        assert_eq!(ObjectKind::UdpEndpoint.type_name(), "_UDP_ENDPOINT");
        assert_eq!(ObjectKind::UdpEndpoint.as_str(), "udp_endpoint");
        assert_eq!(ScanSpace::Physical.as_str(), "physical");
        assert_eq!(ScanSpace::KernelVirtual.as_str(), "kernel_virtual");
    }

    #[test]
    fn microsofts_address_family_constants_are_used_not_the_posix_ones() {
        // AF_INET6 is 30 on BSD and 23 on Windows. The value in the image is
        // Windows', and using the POSIX one would classify every IPv6 socket as
        // an unknown family and drop it.
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 23);
    }

    // ── The orchestrated stage ──────────────────────────────────────────────

    #[test]
    fn the_survey_keeps_its_sweep_when_tcpip_cannot_be_located_and_claims_nothing_hidden() {
        // The stage this wires exists because the walk was implemented and
        // never run. Where the walk cannot run — no tcpip symbol pack, which is
        // the ordinary case — the sweep is still evidence, and the absent
        // second view must not read as "every endpoint here was also in the
        // kernel's tables".
        let mut image = tcp_endpoint_image(AF_INET, 4);
        image.write(IN_ADDR_LOCAL_AT, &[10, 0, 0, 5]);
        image.write(IN_ADDR_REMOTE_AT, &[203, 0, 113, 7]);
        let (profile, symbols) = symbols_for(image, false);

        let survey = survey_network(
            &profile,
            &symbols,
            &NetscanConfig::default(),
            &NetstatConfig::default(),
        )
        .expect("the sweep half always runs");

        assert_eq!(survey.scan.endpoints.len(), 1, "the sweep is not lost");
        assert!(survey.walk.is_none());
        assert!(
            survey.walk_unavailable.is_some(),
            "the reason the walk did not run is stated"
        );
        assert!(!survey.comparable);
        assert!(survey.swept_only.is_empty(), "no view to subtract");
        assert!(
            !survey.is_complete(),
            "one view is not the cross-view this stage exists to produce"
        );
        assert!(survey
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("tcpip.sys")));

        let json = survey.to_json();
        // The sweep stays where a consumer has always found it.
        assert_eq!(json["endpoint_count"], 1);
        assert_eq!(json["space"], "kernel_virtual");
        // With the second view, and its absence, beside it.
        assert_eq!(json["walk"], serde_json::Value::Null);
        assert!(json["walk_unavailable"].is_string());
        assert_eq!(json["comparable"], false);
        assert_eq!(json["survey_complete"], false);
        // The sweep ran end to end, and a consumer that reads one key to decide
        // whether it may quote the record must not be handed that `true`: this
        // record is one view of the machine's connections, not the cross-view
        // the stage exists to produce.
        assert_eq!(json["complete"], false);
        assert_eq!(
            json["sweep_complete"], true,
            "the sweep's own verdict is kept, under a name that says whose it is"
        );
    }

    #[test]
    fn locating_tcpip_refuses_rather_than_guessing_a_load_address() {
        // A wrong load address turns every tcpip symbol into an address in some
        // other driver, and the tables read from it parse.
        let mut image = tcp_endpoint_image(AF_INET, 4);
        image.write(IN_ADDR_LOCAL_AT, &[10, 0, 0, 5]);
        let (profile, _symbols) = symbols_for(image, false);
        let err = locate_tcpip(&profile).expect_err("this fixture has no kernel module list");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("tcpip.sys"), "{err}");
    }
}
