//! `netstat`: the same sockets, reached by walking tcpip.sys's own tracking
//! structures instead of by scanning for them.
//!
//! Where [`netscan`](super::netscan) sweeps memory for pool tags, this walks the
//! three structures the running kernel itself uses to find a socket:
//!
//! * the **partition table**, an array of per-processor partitions each holding
//!   a hash table of live `_TCP_ENDPOINT`s — the established connections;
//! * the **TCP port pool**, indexed by port number, holding `_TCP_LISTENER`
//!   chains — the listening services;
//! * the **UDP port pool**, the same shape, holding `_UDP_ENDPOINT` chains.
//!
//! # Why run it as well as the sweep
//!
//! Neither view is a superset of the other, and the difference between them is
//! itself a finding:
//!
//! * A socket the **walk** finds and the **sweep** misses means the sweep did
//!   not cover the memory it was in — a gap in the acquisition, or an object in
//!   a region the sweep was bounded away from.
//! * A socket the **sweep** finds and the **walk** misses is either historical
//!   (the connection closed, so tcpip unlinked it while the allocation survives)
//!   or **hidden** (something unlinked it deliberately). Which of the two it is
//!   depends on the object's state and creation time, which is exactly why the
//!   sweep's rows carry both.
//!
//! That comparison only means anything if the two are genuinely independent, so
//! this module never falls back to the sweep. When tcpip's symbols do not permit
//! the walk it returns [`NetError::Unsupported`] naming the symbols it needed —
//! never the sweep's results under another name, and never an empty list, which
//! would read as "nothing was connected".
//!
//! # What this needs that the sweep does not
//!
//! tcpip.sys's *symbols*, not just its types: `PartitionTable`, `PartitionCount`
//! and either the older `TcpPortPool`/`UdpPortPool` globals or the newer
//! `TcpCompartmentSet`/`UdpCompartmentSet` ones that Windows 10 build 14251 and
//! later use. Those live in `tcpip.pdb` and are addressed relative to the load
//! address of tcpip.sys, which some other stage has to find — see
//! [`TcpipModule`].

use std::collections::HashSet;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::binding::{required_offset, required_size};
use seance_memory::object::{ListSpec, ListStop, Obj, ObjError};
use seance_memory::Incomplete;
use seance_symbols::SymbolTable;

use crate::module::STAGE_NETWORK;
use crate::profile::WindowsProfile;

use super::decode::{decode, target_address};
use super::{
    NetError, NetworkEndpoint, NetworkSymbols, ObjectKind, PoolTag, Readers, Rejected,
    TYPE_TCP_ENDPOINT, TYPE_TCP_LISTENER, TYPE_UDP_ENDPOINT,
};

/// Types the walk reads that the sweep does not.
const TYPE_PARTITION_TABLE: &str = "_PARTITION_TABLE";
const TYPE_PARTITION: &str = "_PARTITION";
const TYPE_INET_PORT_POOL: &str = "_INET_PORT_POOL";
const TYPE_PORT_ASSIGNMENT: &str = "_PORT_ASSIGNMENT";
const TYPE_PORT_ASSIGNMENT_LIST: &str = "_PORT_ASSIGNMENT_LIST";
const TYPE_INET_COMPARTMENT_SET: &str = "_INET_COMPARTMENT_SET";
const TYPE_INET_COMPARTMENT: &str = "_INET_COMPARTMENT";
const TYPE_PROTOCOL_COMPARTMENT: &str = "_PROTOCOL_COMPARTMENT";
const TYPE_HASH_TABLE: &str = "_RTL_DYNAMIC_HASH_TABLE";
const TYPE_BITMAP: &str = "_RTL_BITMAP";
const TYPE_LIST_ENTRY: &str = "_LIST_ENTRY";

/// tcpip symbols the two halves of the walk need.
const SYM_PARTITION_TABLE: &str = "PartitionTable";
const SYM_PARTITION_COUNT: &str = "PartitionCount";
const SYM_TCP_PORT_POOL: &str = "TcpPortPool";
const SYM_UDP_PORT_POOL: &str = "UdpPortPool";
const SYM_TCP_COMPARTMENT_SET: &str = "TcpCompartmentSet";
const SYM_UDP_COMPARTMENT_SET: &str = "UdpCompartmentSet";

/// Ceiling on partitions walked.
///
/// `PartitionCount` is a single byte in every build, so 256 is its whole range;
/// stating it here means a symbol table that widened the field cannot turn one
/// image into an unbounded walk.
pub const MAX_PARTITIONS: u64 = 256;

/// Ceiling on hash-table buckets examined per partition.
///
/// The endpoint hash table's `TableSize` is read out of the image and is
/// routinely wrong in smeared acquisitions — values in the billions have been
/// seen, which are addresses rather than counts. Bounding it turns a hung
/// analysis into a stated cap.
pub const MAX_HASH_BUCKETS: u64 = 4096;

/// Ceiling on entries followed out of one hash-table bucket.
pub const MAX_BUCKET_ENTRIES: usize = 4096;

/// Ceiling on the port bitmap, in bytes.
///
/// The bitmap covers 65,536 ports, which is 8,192 bytes on every build seen.
/// Ten times that leaves room for a change while refusing a `SizeOfBitMap` that
/// is really the low half of a pointer.
pub const MAX_BITMAP_BYTES: u64 = 81_920;

/// Ceiling on objects followed along one port's `Next` chain.
///
/// A port used on many interfaces produces a chain; a corrupt one produces an
/// endless walk. Cycle detection catches the repeating case and this catches the
/// rest.
pub const MAX_PORT_CHAIN: usize = 4096;

/// Ceiling on endpoints one walk will return.
pub const MAX_WALK_ENDPOINTS: usize = 200_000;

/// How many bytes of the port bitmap are read in one go.
const BITMAP_CHUNK: u64 = 4096;

/// Mask that clears the flag bits tcpip keeps in the low bits of a stored
/// object pointer.
///
/// The kernel encodes a couple of bits of state into the bottom of these
/// pointers and clears them before use. Following one without masking lands two
/// or three bytes into the object, and every member read from there is off by
/// the same amount — which produces a full row of plausible nonsense rather than
/// a failure.
const POINTER_FLAG_MASK: u64 = !0b11;

/// Where tcpip.sys is loaded, and the symbols that describe it.
///
/// The walk needs both: a symbol's address in `tcpip.pdb` is relative to the
/// image, so `PartitionTable` is only meaningful once added to the load address.
/// Finding that load address is the module stage's job — it is the entry in
/// `PsLoadedModuleList` whose `BaseDllName` is `tcpip.sys` — and it is passed in
/// rather than rediscovered here so that a report can state one provenance for
/// it.
#[derive(Debug, Clone)]
pub struct TcpipModule {
    /// tcpip.sys's load address in the kernel's virtual address space.
    pub base: u64,
    /// Symbols compiled from `tcpip.pdb` for this exact driver build.
    pub symbols: Arc<SymbolTable>,
}

impl TcpipModule {
    /// A module description from a load address and its symbols.
    pub fn new(base: u64, symbols: Arc<SymbolTable>) -> Self {
        Self { base, symbols }
    }

    /// The virtual address of a tcpip symbol.
    ///
    /// # Errors
    ///
    /// [`NetError::Unsupported`] naming the symbol when this driver build does
    /// not export it, and [`ObjError::Overflow`] if the load address plus the
    /// symbol's own address does not fit in 64 bits — never a wrapped address,
    /// which would be read from successfully and mean nothing.
    fn address_of(&self, symbol: &str) -> Result<u64, NetError> {
        if !self.symbols.has_symbol(symbol) {
            return Err(NetError::unsupported(format!(
                "tcpip.sys's symbols for this build do not include '{symbol}'"
            )));
        }
        let relative = self.symbols.symbol_address(symbol)?;
        self.base.checked_add(relative).ok_or_else(|| {
            NetError::Object(ObjError::Overflow(format!(
                "tcpip.sys at {:#x} plus the address of '{symbol}' does not fit in 64 bits",
                self.base
            )))
        })
    }
}

/// Bounds for one walk.
#[derive(Debug, Clone)]
pub struct NetstatConfig {
    /// Ceiling on partitions walked.
    pub max_partitions: u64,
    /// Ceiling on hash-table buckets examined per partition.
    pub max_hash_buckets: u64,
    /// Ceiling on entries followed out of one bucket.
    pub max_bucket_entries: usize,
    /// Ceiling on the port bitmap, in bytes.
    pub max_bitmap_bytes: u64,
    /// Ceiling on objects followed along one port's `Next` chain.
    pub max_port_chain: usize,
    /// Ceiling on endpoints returned.
    pub max_endpoints: usize,
    /// Ceiling on individually recorded rejections.
    pub max_recorded_rejections: usize,
}

impl Default for NetstatConfig {
    fn default() -> Self {
        Self {
            max_partitions: MAX_PARTITIONS,
            max_hash_buckets: MAX_HASH_BUCKETS,
            max_bucket_entries: MAX_BUCKET_ENTRIES,
            max_bitmap_bytes: MAX_BITMAP_BYTES,
            max_port_chain: MAX_PORT_CHAIN,
            max_endpoints: MAX_WALK_ENDPOINTS,
            max_recorded_rejections: super::MAX_RECORDED_REJECTIONS,
        }
    }
}

/// Everything one walk reached, and everything it could not.
#[derive(Debug, Clone)]
pub struct NetstatOutcome {
    /// Sockets the walk reached, ascending by address.
    pub endpoints: Vec<NetworkEndpoint>,
    /// Objects the walk reached that did not decode.
    pub rejected: Vec<Rejected>,
    /// How many were rejected in total, exact even when the list was capped.
    pub rejected_total: usize,
    /// How many partitions were walked.
    pub partitions: u64,
    /// How many TCP ports the port bitmap said were in use.
    pub tcp_ports: usize,
    /// How many UDP ports the port bitmap said were in use.
    pub udp_ports: usize,
    /// Whether the partition half of the walk ran.
    pub partitions_walked: bool,
    /// Whether the port-pool half of the walk ran.
    pub port_pools_walked: bool,
    /// Everything a report must declare about this result — including which
    /// half of the walk could not be done, and why.
    pub incomplete: Vec<Incomplete>,
}

impl NetstatOutcome {
    /// Whether both halves ran and neither hit a limit.
    ///
    /// A walk that only covered listeners is not a connection list, and this is
    /// the question that stops it being presented as one.
    pub fn is_complete(&self) -> bool {
        self.partitions_walked && self.port_pools_walked && self.incomplete.is_empty()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "endpoints": self.endpoints.iter().map(|e| e.to_json()).collect::<Vec<_>>(),
            "endpoint_count": self.endpoints.len(),
            "rejected_total": self.rejected_total,
            "rejected": self
                .rejected
                .iter()
                .map(|r| serde_json::json!({
                    "address": r.address,
                    "source": r.tag,
                    "reason": r.reason,
                }))
                .collect::<Vec<_>>(),
            "partitions": self.partitions,
            "tcp_ports": self.tcp_ports,
            "udp_ports": self.udp_ports,
            "partitions_walked": self.partitions_walked,
            "port_pools_walked": self.port_pools_walked,
            "complete": self.is_complete(),
            "incomplete": self.incomplete.iter().map(|i| i.to_json()).collect::<Vec<_>>(),
        })
    }
}

/// Walk tcpip.sys's partition table and port pools.
///
/// # What an examiner learns
///
/// The sockets the kernel itself would have listed a moment before acquisition:
/// established connections from the partition table, listening TCP services and
/// bound UDP sockets from the port pools. Compared against
/// [`netscan`](super::netscan), the difference in either direction is a finding
/// in its own right.
///
/// # What a wrong answer looks like
///
/// A short list presented as the whole one. A walk that reached only the port
/// pools shows every listening service and no established connection, which
/// reads exactly like a machine that was idle. [`NetstatOutcome::is_complete`]
/// and the entries in [`NetstatOutcome::incomplete`] exist so that cannot pass
/// unnoticed.
///
/// # Errors
///
/// [`NetError::Unsupported`] when *neither* half of the walk is possible on this
/// driver build, naming the symbols and types that were missing. When one half
/// is possible it runs, and the other half's reason is recorded in
/// [`NetstatOutcome::incomplete`] rather than discarded.
pub fn netstat(
    profile: &WindowsProfile,
    symbols: &NetworkSymbols,
    tcpip: &TcpipModule,
    config: &NetstatConfig,
) -> Result<NetstatOutcome, NetError> {
    let readers = Readers::virtual_only(profile, symbols);
    let mut state = Walk {
        endpoints: Vec::new(),
        seen: HashSet::new(),
        rejected: Vec::new(),
        rejected_total: 0,
        incomplete: Vec::new(),
        config: config.clone(),
    };

    let mut partitions = 0u64;
    let partitions_result = walk_partitions(&readers, symbols, tcpip, &mut state, &mut partitions);
    let partitions_walked = match partitions_result {
        Ok(()) => true,
        Err(err) => {
            state.incomplete.push(Incomplete::new(
                err.incomplete_reason(),
                format!(
                    "established TCP connections could not be enumerated from tcpip.sys's \
                     partition table, so this list holds no established connections at all: {err}"
                ),
            ));
            false
        }
    };

    let mut tcp_ports = 0usize;
    let mut udp_ports = 0usize;
    let pools_result = walk_port_pools(
        &readers,
        symbols,
        tcpip,
        &mut state,
        &mut tcp_ports,
        &mut udp_ports,
    );
    let port_pools_walked = match pools_result {
        Ok(()) => true,
        Err(err) => {
            state.incomplete.push(Incomplete::new(
                err.incomplete_reason(),
                format!(
                    "listening sockets could not be enumerated from tcpip.sys's port pools, so \
                     this list holds no listeners at all: {err}"
                ),
            ));
            false
        }
    };

    if !partitions_walked && !port_pools_walked {
        return Err(NetError::unsupported(format!(
            "neither half of the walk is possible on this tcpip.sys build. {}",
            state
                .incomplete
                .iter()
                .map(|i| i.detail.clone())
                .collect::<Vec<_>>()
                .join(" ")
        )));
    }

    state.endpoints.sort_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| a.protocol.as_str().cmp(b.protocol.as_str()))
    });

    if state.rejected_total > state.rejected.len() {
        state.incomplete.push(Incomplete::new(
            IncompleteReason::CapReached,
            format!(
                "{} objects the walk reached did not decode and only {} are listed individually",
                state.rejected_total,
                state.rejected.len()
            ),
        ));
    }

    Ok(NetstatOutcome {
        endpoints: state.endpoints,
        rejected: state.rejected,
        rejected_total: state.rejected_total,
        partitions,
        tcp_ports,
        udp_ports,
        partitions_walked,
        port_pools_walked,
        incomplete: state.incomplete,
    })
}

/// Everything one walk accumulates.
struct Walk {
    endpoints: Vec<NetworkEndpoint>,
    /// Object addresses already turned into rows.
    ///
    /// The partition hash table can reach one endpoint from more than one place
    /// after a rehash, and a duplicated row inflates a connection count in a
    /// report. Recording the address is enough: two rows for one address are the
    /// same object, and two objects never share an address.
    seen: HashSet<u64>,
    rejected: Vec<Rejected>,
    rejected_total: usize,
    incomplete: Vec<Incomplete>,
    config: NetstatConfig,
}

impl Walk {
    /// Decode one object the walk reached, or record why it did not decode.
    fn admit(
        &mut self,
        readers: &Readers,
        symbols: &NetworkSymbols,
        source: &'static str,
        kind: ObjectKind,
        address: u64,
    ) -> bool {
        if self.endpoints.len() >= self.config.max_endpoints {
            return false;
        }
        if !self.seen.insert(address) {
            return true;
        }
        let tag = PoolTag { tag: source, kind };
        match decode(readers, symbols, tag, address, Vec::new()) {
            Ok(mut rows) => self.endpoints.append(&mut rows),
            Err(reason) => {
                self.rejected_total = self.rejected_total.saturating_add(1);
                if self.rejected.len() < self.config.max_recorded_rejections {
                    self.rejected.push(Rejected {
                        address,
                        tag: source,
                        reason,
                    });
                }
            }
        }
        true
    }

    /// Record something the walk could not do without abandoning it.
    ///
    /// Bounded, because a badly smeared image can produce one note per bucket.
    /// Reaching the bound is itself recorded: a truncated list of gaps must not
    /// read as the whole list of gaps.
    fn note(&mut self, reason: IncompleteReason, detail: String) {
        const MAX_NOTES: usize = 64;
        match self.incomplete.len() {
            len if len < MAX_NOTES => self.incomplete.push(Incomplete::new(reason, detail)),
            len if len == MAX_NOTES => self.incomplete.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!("further notes about this walk were suppressed after {MAX_NOTES}"),
            )),
            _ => {}
        }
    }
}

/// Established TCP connections, from the per-processor partition table.
fn walk_partitions(
    readers: &Readers,
    symbols: &NetworkSymbols,
    tcpip: &TcpipModule,
    state: &mut Walk,
    partitions_walked: &mut u64,
) -> Result<(), NetError> {
    let network = symbols.network_table();
    let kernel = symbols.kernel_table();
    // `_PARTITION_TABLE.Partitions`, `_PARTITION` and `_TCP_ENDPOINT.ListEntry`
    // are deliberately not pre-flighted here: each is bound below, at the point
    // its value is used, through the binding — which says which stage stopped
    // and what stopping cost. `_PARTITION.Endpoints` stays, because it is read
    // by name rather than by offset and so has no value to bind, and it is
    // checked *after* the partition's width so that a build with no
    // `_PARTITION` at all is answered by the binding's message rather than by
    // this one.
    super::require(kernel, TYPE_LIST_ENTRY, &["Flink"])?;
    super::require(
        kernel,
        TYPE_HASH_TABLE,
        &["TableSize", "NumEntries", "Directory"],
    )?;
    let table_pointer_at = tcpip.address_of(SYM_PARTITION_TABLE)?;
    let count_at = tcpip.address_of(SYM_PARTITION_COUNT)?;

    let table_address = readers.kernel.read_pointer_at(table_pointer_at)?;
    if table_address == 0 {
        return Err(NetError::unsupported(
            "tcpip.sys's 'PartitionTable' pointer is null in this image, so there is no partition \
             table to walk",
        ));
    }
    // `PartitionCount` is one byte on every build. Reading it as anything wider
    // would pick up whatever global follows it and walk that many partitions.
    let count = u64::from(readers.kernel.read_bytes(count_at, 1)?[0]);
    if count == 0 {
        return Err(NetError::unsupported(
            "tcpip.sys reports a partition count of zero, which no running kernel has",
        ));
    }
    let count = count.min(state.config.max_partitions);

    // All three are required, and correctly so: without the array's offset
    // there is no first partition, without the stride there is no second, and
    // without the endpoint's list link an endpoint found on a bucket cannot be
    // stepped back to its own start. What each failure has to carry is the
    // stage that stopped and what stopping cost, which a bare `SymbolError`
    // through a transparent variant does not.
    let partitions_offset = required_offset(
        &readers.network,
        STAGE_NETWORK,
        &[TYPE_PARTITION_TABLE],
        &["Partitions"],
        "tcpip.sys's per-processor partitions cannot be located, so no established TCP \
         connection can be listed from the partition table",
    )?;
    let stride = required_size(
        network,
        STAGE_NETWORK,
        &[TYPE_PARTITION],
        "the per-processor partitions have no width, so no partition beyond the first can be \
         reached and connections handled by every other processor would go unlisted",
    )?;
    if stride == 0 {
        return Err(NetError::unsupported(format!(
            "'{TYPE_PARTITION}' declares a size of zero, so the partitions cannot be stepped \
             through"
        )));
    }
    super::require(network, TYPE_PARTITION, &["Endpoints"])?;
    let list_entry_offset = required_offset(
        &readers.network,
        STAGE_NETWORK,
        &[TYPE_TCP_ENDPOINT],
        &["ListEntry"],
        "an endpoint found on a hash bucket cannot be stepped back to the start of its own \
         structure, so no established TCP connection can be decoded",
    )?;
    // The bucket array is an array of `_LIST_ENTRY` heads, which is two pointers
    // wide. Taking the stride from the pointer width rather than from a constant
    // is what keeps the 32-bit case right.
    let bucket_stride = symbols.pointer_size().saturating_mul(2);

    for index in 0..count {
        let offset = index
            .checked_mul(stride)
            .and_then(|within| partitions_offset.checked_add(within))
            .and_then(|offset| table_address.checked_add(offset));
        let Some(partition_address) = offset else {
            state.note(
                IncompleteReason::UnresolvedStructure,
                format!("partition {index} lies past the end of the 64-bit address space"),
            );
            break;
        };
        *partitions_walked = partitions_walked.saturating_add(1);

        let partition = match readers.network.object(partition_address, TYPE_PARTITION) {
            Ok(partition) => partition,
            Err(err) => {
                state.note(
                    err.incomplete_reason(),
                    format!("partition {index} at {partition_address:#x} could not be read: {err}"),
                );
                continue;
            }
        };
        let hash_table = match target_address(&partition, "Endpoints") {
            Ok(Some(address)) => address,
            Ok(None) => continue,
            Err(err) => {
                state.note(
                    err.incomplete_reason(),
                    format!("partition {index}'s endpoint hash table could not be reached: {err}"),
                );
                continue;
            }
        };

        walk_hash_table(
            readers,
            symbols,
            state,
            hash_table,
            bucket_stride,
            list_entry_offset,
            index,
        );
    }

    Ok(())
}

/// One partition's endpoint hash table.
///
/// The table's directory is an array of `_LIST_ENTRY` bucket heads, and each
/// bucket is a circular list of `_TCP_ENDPOINT.ListEntry` links. Walking the
/// whole of each bucket rather than taking only its first entry matters: two
/// connections that hash together are both real, and the second one silently
/// missing is a connection absent from a report.
#[allow(clippy::too_many_arguments)]
fn walk_hash_table(
    readers: &Readers,
    symbols: &NetworkSymbols,
    state: &mut Walk,
    hash_table: u64,
    bucket_stride: u64,
    list_entry_offset: u64,
    partition: u64,
) {
    let table = match readers.kernel.object(hash_table, TYPE_HASH_TABLE) {
        Ok(table) => table,
        Err(err) => {
            state.note(
                err.incomplete_reason(),
                format!("partition {partition}'s hash table could not be read: {err}"),
            );
            return;
        }
    };

    let entries = read_unsigned(&table, "NumEntries");
    let Some(entries) = entries else {
        state.note(
            IncompleteReason::UnresolvedStructure,
            format!("partition {partition}'s hash table has no readable entry count"),
        );
        return;
    };
    if entries == 0 {
        return;
    }

    let Some(size) = read_unsigned(&table, "TableSize") else {
        state.note(
            IncompleteReason::UnresolvedStructure,
            format!("partition {partition}'s hash table has no readable size"),
        );
        return;
    };
    if size > state.config.max_hash_buckets {
        // A `TableSize` in the millions is an address that landed in the field,
        // which happens in smeared acquisitions. Walking it would be a hang.
        state.note(
            IncompleteReason::CapReached,
            format!(
                "partition {partition}'s hash table declares {size} buckets, above the {} this \
                 walk will follow, so its endpoints were not enumerated",
                state.config.max_hash_buckets
            ),
        );
        return;
    }

    let directory = match table.pointer("Directory") {
        Ok(0) => return,
        Ok(directory) => directory,
        Err(err) => {
            state.note(
                err.incomplete_reason(),
                format!("partition {partition}'s hash table directory could not be read: {err}"),
            );
            return;
        }
    };

    let spec =
        ListSpec::new(TYPE_LIST_ENTRY, "Flink").with_max_entries(state.config.max_bucket_entries);
    let mut unreadable = 0usize;
    for bucket in 0..size {
        let Some(head) = bucket
            .checked_mul(bucket_stride)
            .and_then(|offset| directory.checked_add(offset))
        else {
            break;
        };
        let walk = match readers.kernel.walk_list(head, &spec) {
            Ok(walk) => walk,
            Err(err) => {
                state.note(
                    err.incomplete_reason(),
                    format!("the bucket list could not be started: {err}"),
                );
                return;
            }
        };
        let (links, stop) = walk.walk_to_end();
        for link in links {
            let Some(address) = link.address().checked_sub(list_entry_offset) else {
                continue;
            };
            if !state.admit(
                readers,
                symbols,
                "PartitionTable",
                ObjectKind::TcpEndpoint,
                address,
            ) {
                state.note(
                    IncompleteReason::CapReached,
                    "the walk stopped at its endpoint cap; tcpip's tables hold more".to_string(),
                );
                return;
            }
        }
        if !matches!(stop, ListStop::Wrapped) {
            unreadable = unreadable.saturating_add(1);
        }
    }

    if unreadable > 0 {
        state.note(
            IncompleteReason::ShortRead,
            format!(
                "{unreadable} of partition {partition}'s {size} hash buckets did not close, so \
                 connections in them may be missing"
            ),
        );
    }
}

/// Listening TCP sockets and bound UDP sockets, from the two port pools.
fn walk_port_pools(
    readers: &Readers,
    symbols: &NetworkSymbols,
    tcpip: &TcpipModule,
    state: &mut Walk,
    tcp_ports: &mut usize,
    udp_ports: &mut usize,
) -> Result<(), NetError> {
    let network = symbols.network_table();
    let kernel = symbols.kernel_table();
    super::require(
        network,
        TYPE_INET_PORT_POOL,
        &["PortBitMap", "PortAssignments"],
    )?;
    super::require(network, TYPE_PORT_ASSIGNMENT, &["InPaBigPoolBase"])?;
    super::require(network, TYPE_PORT_ASSIGNMENT_LIST, &["Assignments"])?;
    super::require(network, TYPE_TCP_LISTENER, &["Next"])?;
    super::require(network, TYPE_UDP_ENDPOINT, &["Next"])?;
    super::require(kernel, TYPE_BITMAP, &["SizeOfBitMap", "Buffer"])?;

    let (tcp_pool, udp_pool) = find_port_pools(readers, symbols, tcpip)?;

    let tcp = ports_in_use(readers, state, tcp_pool, "TCP")?;
    *tcp_ports = tcp.len();
    for port in tcp {
        follow_port_chain(
            readers,
            symbols,
            state,
            tcp_pool,
            port,
            ObjectKind::TcpListener,
            "TcpPortPool",
        );
    }

    let udp = ports_in_use(readers, state, udp_pool, "UDP")?;
    *udp_ports = udp.len();
    for port in udp {
        follow_port_chain(
            readers,
            symbols,
            state,
            udp_pool,
            port,
            ObjectKind::UdpEndpoint,
            "UdpPortPool",
        );
    }

    Ok(())
}

/// The addresses of the TCP and UDP port pools.
///
/// Windows before build 14251 exports the pools directly as `TcpPortPool` and
/// `UdpPortPool`; later builds export compartment *sets* instead, and the pool
/// is three pointers inside. Both are tried, in that order, and a build that has
/// neither is named rather than guessed at.
fn find_port_pools(
    readers: &Readers,
    symbols: &NetworkSymbols,
    tcpip: &TcpipModule,
) -> Result<(u64, u64), NetError> {
    if tcpip.symbols.has_symbol(SYM_TCP_PORT_POOL) && tcpip.symbols.has_symbol(SYM_UDP_PORT_POOL) {
        let tcp = readers
            .kernel
            .read_pointer_at(tcpip.address_of(SYM_TCP_PORT_POOL)?)?;
        let udp = readers
            .kernel
            .read_pointer_at(tcpip.address_of(SYM_UDP_PORT_POOL)?)?;
        if tcp == 0 || udp == 0 {
            return Err(NetError::unsupported(
                "tcpip.sys's port-pool pointers are null in this image",
            ));
        }
        return Ok((tcp, udp));
    }

    if tcpip.symbols.has_symbol(SYM_TCP_COMPARTMENT_SET)
        && tcpip.symbols.has_symbol(SYM_UDP_COMPARTMENT_SET)
    {
        let network = symbols.network_table();
        super::require(network, TYPE_INET_COMPARTMENT_SET, &["InetCompartment"])?;
        super::require(network, TYPE_INET_COMPARTMENT, &["ProtocolCompartment"])?;
        super::require(network, TYPE_PROTOCOL_COMPARTMENT, &["PortPool"])?;
        let tcp = pool_through_compartment(readers, tcpip, SYM_TCP_COMPARTMENT_SET)?;
        let udp = pool_through_compartment(readers, tcpip, SYM_UDP_COMPARTMENT_SET)?;
        return Ok((tcp, udp));
    }

    Err(NetError::unsupported(format!(
        "tcpip.sys's symbols for this build have neither '{SYM_TCP_PORT_POOL}'/\
         '{SYM_UDP_PORT_POOL}' nor '{SYM_TCP_COMPARTMENT_SET}'/'{SYM_UDP_COMPARTMENT_SET}', so \
         the port pools cannot be located"
    )))
}

/// One port pool, reached through a compartment set.
fn pool_through_compartment(
    readers: &Readers,
    tcpip: &TcpipModule,
    symbol: &str,
) -> Result<u64, NetError> {
    let set_address = readers.kernel.read_pointer_at(tcpip.address_of(symbol)?)?;
    if set_address == 0 {
        return Err(NetError::unsupported(format!(
            "tcpip.sys's '{symbol}' pointer is null in this image"
        )));
    }
    let set = readers
        .network
        .object(set_address, TYPE_INET_COMPARTMENT_SET)?;
    let compartment = target_address(&set, "InetCompartment")?.ok_or_else(|| {
        NetError::unsupported(format!("'{symbol}' has no compartment in this image"))
    })?;
    let compartment = readers.network.object(compartment, TYPE_INET_COMPARTMENT)?;
    let protocol = target_address(&compartment, "ProtocolCompartment")?.ok_or_else(|| {
        NetError::unsupported(format!(
            "'{symbol}' has no protocol compartment in this image"
        ))
    })?;
    let protocol = readers
        .network
        .object(protocol, TYPE_PROTOCOL_COMPARTMENT)?;
    target_address(&protocol, "PortPool")?
        .ok_or_else(|| NetError::unsupported(format!("'{symbol}' has no port pool in this image")))
}

/// Which ports the pool's bitmap says are in use.
///
/// One bit per port, 65,536 of them. Port 0 is skipped because it is never a
/// bound port: it is the value a socket carries before it is bound, and chasing
/// its assignment list finds whatever the pool happens to keep at index zero.
fn ports_in_use(
    readers: &Readers,
    state: &mut Walk,
    pool_address: u64,
    label: &str,
) -> Result<Vec<u32>, NetError> {
    let pool = readers.network.object(pool_address, TYPE_INET_PORT_POOL)?;
    // `PortBitMap` is an `_RTL_BITMAP` embedded in the pool on every build seen,
    // but the table is what says so. Taking its address unconditionally would,
    // on a build that made it a pointer, read the pointer's own eight bytes as
    // `SizeOfBitMap` and `Buffer` — a bitmap size and a buffer address that are
    // really two halves of one address, and which decode without complaint.
    let Some(bitmap_address) = target_address(&pool, "PortBitMap")? else {
        state.note(
            IncompleteReason::UnresolvedStructure,
            format!("the {label} port pool's bitmap pointer is null"),
        );
        return Ok(Vec::new());
    };
    let bitmap = readers.kernel.object(bitmap_address, TYPE_BITMAP)?;

    let Some(bits) = read_unsigned(&bitmap, "SizeOfBitMap") else {
        return Err(NetError::unsupported(format!(
            "the {label} port pool's bitmap has no readable size"
        )));
    };
    let buffer = bitmap.pointer("Buffer")?;
    if buffer == 0 {
        state.note(
            IncompleteReason::UnresolvedStructure,
            format!("the {label} port pool's bitmap buffer is null"),
        );
        return Ok(Vec::new());
    }
    let bytes = bits / 8;
    if bytes == 0 || bytes > state.config.max_bitmap_bytes {
        // A `SizeOfBitMap` in the billions is an address that landed in the
        // field, which is common in smeared acquisitions.
        state.note(
            IncompleteReason::CapReached,
            format!(
                "the {label} port pool declares a bitmap of {bytes} byte(s), which is not a port \
                 bitmap, so no {label} sockets were enumerated"
            ),
        );
        return Ok(Vec::new());
    }

    let mut ports = Vec::new();
    let mut offset = 0u64;
    while offset < bytes {
        let length = BITMAP_CHUNK.min(bytes - offset);
        let Some(at) = buffer.checked_add(offset) else {
            break;
        };
        match readers.kernel.read_bytes(at, length) {
            Ok(chunk) => set_bit_indices(&chunk, offset, &mut ports),
            Err(err) => {
                state.note(
                    err.incomplete_reason(),
                    format!(
                        "{length} byte(s) of the {label} port bitmap at {at:#x} could not be \
                         read, so ports in that range were not enumerated: {err}"
                    ),
                );
            }
        }
        offset = offset.saturating_add(length);
    }
    ports.retain(|&port| port != 0);
    Ok(ports)
}

/// Every port whose bit is set in a slice of the bitmap.
///
/// `base` is the slice's byte offset within the whole bitmap, so a chunked read
/// produces the same port numbers a single read would. Getting that wrong shifts
/// every port in a chunk by a multiple of 32,768.
fn set_bit_indices(chunk: &[u8], base: u64, into: &mut Vec<u32>) {
    for (index, byte) in chunk.iter().enumerate() {
        if *byte == 0 {
            continue;
        }
        let byte_offset = base.saturating_add(index as u64);
        for bit in 0..8u32 {
            if *byte & (1u8 << bit) != 0 {
                let port = byte_offset.saturating_mul(8).saturating_add(u64::from(bit));
                if let Ok(port) = u32::try_from(port) {
                    into.push(port);
                }
            }
        }
    }
}

/// Every object assigned to one port, following the `Next` chain.
///
/// One port used on several interfaces produces several objects, chained through
/// `Next`. The chain is bounded and cycle-checked: a corrupt `Next` that points
/// back into the chain would otherwise be walked forever, and the same socket
/// reported until the report was useless.
#[allow(clippy::too_many_arguments)]
fn follow_port_chain(
    readers: &Readers,
    symbols: &NetworkSymbols,
    state: &mut Walk,
    pool_address: u64,
    port: u32,
    kind: ObjectKind,
    source: &'static str,
) {
    let type_name = kind.type_name();
    let next_offset = match symbols.network_table().member_offset(type_name, "Next") {
        Ok(offset) => offset,
        Err(err) => {
            state.note(
                IncompleteReason::UnresolvedStructure,
                format!("'{type_name}.Next' could not be resolved: {err}"),
            );
            return;
        }
    };

    let first = match assignment_for_port(readers, pool_address, port) {
        Ok(Some(first)) => first,
        Ok(None) => return,
        Err(err) => {
            state.note(
                err.incomplete_reason(),
                format!("port {port}'s assignment could not be read: {err}"),
            );
            return;
        }
    };

    let mut visited: HashSet<u64> = HashSet::new();
    let mut inside = first;
    for _ in 0..state.config.max_port_chain {
        let Some(address) = inside.checked_sub(next_offset) else {
            state.note(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "port {port}'s object link points {next_offset} byte(s) inside a structure \
                     that would start below address zero"
                ),
            );
            return;
        };
        if !visited.insert(address) {
            state.note(
                IncompleteReason::UnresolvedStructure,
                format!("port {port}'s object chain returns to {address:#x} and does not end"),
            );
            return;
        }
        if !state.admit(readers, symbols, source, kind, address) {
            state.note(
                IncompleteReason::CapReached,
                "the walk stopped at its endpoint cap; tcpip's tables hold more".to_string(),
            );
            return;
        }

        let object = match readers.network.object(address, type_name) {
            Ok(object) => object,
            Err(_) => return,
        };
        let next = match object.pointer("Next") {
            Ok(next) => decode_pointer(next),
            Err(_) => return,
        };
        if next == 0 {
            return;
        }
        inside = next;
    }

    state.note(
        IncompleteReason::CapReached,
        format!(
            "port {port}'s object chain was still going after {} objects",
            state.config.max_port_chain
        ),
    );
}

/// The first object assigned to a port, as the port pool records it.
///
/// The pool is two levels deep: the high byte of the port selects a
/// `_PORT_ASSIGNMENT`, and the low byte selects an entry inside its assignment
/// list. Both index lookups are bounds-checked against the counts the symbol
/// table declares, so an out-of-range port reads nothing rather than whatever
/// follows the array.
fn assignment_for_port(
    readers: &Readers,
    pool_address: u64,
    port: u32,
) -> Result<Option<u64>, ObjError> {
    let list_index = u64::from(port >> 8);
    let within = u64::from(port & 0xFF);

    let pool = readers.network.object(pool_address, TYPE_INET_PORT_POOL)?;
    let slot = pool.element_address("PortAssignments", list_index)?;
    let assignment_address = readers.network.read_pointer_at(slot)?;
    if assignment_address == 0 {
        return Ok(None);
    }

    let assignment = readers
        .network
        .object(assignment_address, TYPE_PORT_ASSIGNMENT)?;
    let Some(list_address) = target_address(&assignment, "InPaBigPoolBase")? else {
        return Ok(None);
    };

    let list = readers
        .network
        .object(list_address, TYPE_PORT_ASSIGNMENT_LIST)?;
    let entry = list.element_object("Assignments", within)?;
    let raw = entry.pointer("Entry")?;
    let decoded = decode_pointer(raw);
    Ok(if decoded == 0 { None } else { Some(decoded) })
}

/// Clear the flag bits tcpip keeps in the low bits of a stored object pointer.
///
/// Following an undecoded pointer lands a few bytes into the object, and every
/// member read from there is off by the same amount — which produces a whole row
/// of plausible nonsense rather than a failure anybody would notice.
fn decode_pointer(value: u64) -> u64 {
    value & POINTER_FLAG_MASK
}

/// Read an unsigned member, or `None` if it is missing, unreadable or negative.
fn read_unsigned(object: &Obj, member: &str) -> Option<u64> {
    object.int(member).ok().and_then(|value| value.as_u64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netscan::test_support::{off, profile, table, windows_network_isf, Image};
    use crate::netscan::{Protocol, SocketState};

    /// Where the netstat fixture puts things.
    const TCPIP_BASE: u64 = 0x1_0000;
    const SYM_PARTITION_TABLE_RVA: u64 = 0x100;
    const SYM_PARTITION_COUNT_RVA: u64 = 0x108;
    const SYM_TCP_POOL_RVA: u64 = 0x110;
    const SYM_UDP_POOL_RVA: u64 = 0x118;

    const PARTITION_TABLE: u64 = 0x1_1000;
    const HASH_TABLE: u64 = 0x1_2000;
    const DIRECTORY: u64 = 0x1_3000;
    const TCPE: u64 = 0x1_4000;

    // The two bitmaps are 8 KiB each and must not overlap anything else: a
    // non-zero byte anywhere inside one is a port the walk would then chase.
    const TCP_POOL: u64 = 0x1_8000;
    const UDP_POOL: u64 = 0x2_0000;
    const BITMAP_BUFFER: u64 = 0x2_4000;
    const UDP_BITMAP_BUFFER: u64 = 0x2_6000;
    const PORT_ASSIGNMENT: u64 = 0x2_8000;
    const PORT_ASSIGNMENT_LIST: u64 = 0x2_9000;
    const TCPL_A: u64 = 0x3_0000;
    const TCPL_B: u64 = 0x3_1000;

    const INETAF_V4: u64 = 0x3_8000;
    const ADDRINFO: u64 = 0x3_8100;
    const LOCAL_ADDRESS: u64 = 0x3_8200;
    const LOCAL_ADDRESS_PTR: u64 = 0x3_8300;
    const IN_ADDR_LOCAL: u64 = 0x3_8400;
    const IN_ADDR_REMOTE: u64 = 0x3_8500;
    const EPROCESS: u64 = 0x3_8600;

    const CREATE_TIME: u64 = 132_669_792_000_000_000;

    /// A tcpip ISF carrying only what the walk needs: the four globals.
    fn tcpip_isf(with_partitions: bool, with_pools: bool) -> String {
        let mut symbols = Vec::new();
        if with_partitions {
            symbols.push(format!(
                r#""PartitionTable": {{"address": {SYM_PARTITION_TABLE_RVA},
                    "type": {{"kind": "base", "name": "unsigned char"}}}}"#
            ));
            symbols.push(format!(
                r#""PartitionCount": {{"address": {SYM_PARTITION_COUNT_RVA},
                    "type": {{"kind": "base", "name": "unsigned char"}}}}"#
            ));
        }
        if with_pools {
            symbols.push(format!(
                r#""TcpPortPool": {{"address": {SYM_TCP_POOL_RVA},
                    "type": {{"kind": "base", "name": "unsigned char"}}}}"#
            ));
            symbols.push(format!(
                r#""UdpPortPool": {{"address": {SYM_UDP_POOL_RVA},
                    "type": {{"kind": "base", "name": "unsigned char"}}}}"#
            ));
        }
        format!(
            r#"{{
  "metadata": {{
    "format": "6.2.0",
    "producer": {{"name": "seance-test", "version": "1.0.0"}},
    "windows": {{"pdb": {{"GUID": "BB1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                         "database": "tcpip.pdb", "machine_type": 34404}}}}
  }},
  "base_types": {{
    "pointer": {{"size": 8, "signed": false, "kind": "int", "endian": "little"}},
    "unsigned char": {{"size": 1, "signed": false, "kind": "int", "endian": "little"}}
  }},
  "user_types": {{
    "_TCPIP_ANCHOR": {{"size": 8, "kind": "struct", "fields": {{
      "Reserved": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned char"}}}}
    }}}}
  }},
  "enums": {{}},
  "symbols": {{{joined}}}
}}"#,
            joined = symbols.join(",")
        )
    }

    fn families_and_owner(image: &mut Image) {
        image.put_u16(INETAF_V4 + off::INETAF_FAMILY, 2);
        image.put_u64(EPROCESS + off::EPROCESS_PID, 1234);
        image.write(EPROCESS + off::EPROCESS_NAME, b"svchost.exe");
    }

    /// A `_TCP_ENDPOINT` reachable only through the partition table.
    fn partition_image() -> Image {
        let mut image = Image::new();
        families_and_owner(&mut image);

        image.put_u64(TCPIP_BASE + SYM_PARTITION_TABLE_RVA, PARTITION_TABLE);
        image.write(TCPIP_BASE + SYM_PARTITION_COUNT_RVA, &[1u8]);

        image.put_u64(PARTITION_TABLE + off::PARTITION_ENDPOINTS, HASH_TABLE);
        image.put_u32(HASH_TABLE + off::HASH_TABLE_SIZE, 2);
        image.put_u32(HASH_TABLE + off::HASH_NUM_ENTRIES, 1);
        image.put_u64(HASH_TABLE + off::HASH_DIRECTORY, DIRECTORY);

        // Bucket 0 is empty: its head points at itself.
        image.put_u64(DIRECTORY, DIRECTORY);
        image.put_u64(DIRECTORY + 8, DIRECTORY);
        // Bucket 1 holds one endpoint, linked through its `ListEntry`.
        let bucket = DIRECTORY + 16;
        let link = TCPE + off::TCPE_LIST_ENTRY;
        image.put_u64(bucket, link);
        image.put_u64(bucket + 8, link);
        image.put_u64(link, bucket);
        image.put_u64(link + 8, bucket);

        image.put_u64(TCPE + off::TCPE_INETAF, INETAF_V4);
        image.put_u64(TCPE + off::TCPE_ADDRINFO, ADDRINFO);
        image.put_u32(TCPE + off::TCPE_STATE, 4);
        image.put_port(TCPE + off::TCPE_LOCAL_PORT, 443);
        image.put_port(TCPE + off::TCPE_REMOTE_PORT, 51_000);
        image.put_u64(TCPE + off::TCPE_OWNER, EPROCESS);
        image.put_u64(TCPE + off::TCPE_CREATE_TIME, CREATE_TIME);

        image.put_u64(ADDRINFO + off::ADDRINFO_LOCAL, LOCAL_ADDRESS);
        image.put_u64(ADDRINFO + off::ADDRINFO_REMOTE, IN_ADDR_REMOTE);
        image.put_u64(LOCAL_ADDRESS + off::LOCAL_ADDRESS_PDATA, LOCAL_ADDRESS_PTR);
        image.put_u64(LOCAL_ADDRESS_PTR, IN_ADDR_LOCAL);
        image.write(IN_ADDR_LOCAL, &[10, 1, 1, 1]);
        image.write(IN_ADDR_REMOTE, &[198, 51, 100, 3]);
        image
    }

    /// Two `_TCP_LISTENER`s on one port, reachable only through the TCP port
    /// pool, with the stored pointer carrying tcpip's low-bit flags.
    fn port_pool_image(port: u16) -> Image {
        let mut image = Image::new();
        families_and_owner(&mut image);

        image.put_u64(TCPIP_BASE + SYM_TCP_POOL_RVA, TCP_POOL);
        image.put_u64(TCPIP_BASE + SYM_UDP_POOL_RVA, UDP_POOL);

        // The TCP pool's bitmap has exactly one port set.
        image.put_u32(
            TCP_POOL + off::PORT_POOL_BITMAP + off::BITMAP_SIZE_OF_BITMAP,
            65_536,
        );
        image.put_u64(
            TCP_POOL + off::PORT_POOL_BITMAP + off::BITMAP_BUFFER,
            BITMAP_BUFFER,
        );
        let byte = u64::from(port) / 8;
        let bit = port % 8;
        image.write(BITMAP_BUFFER + byte, &[1u8 << bit]);

        // The UDP pool's bitmap is empty but well formed, so the UDP half runs
        // and finds nothing rather than failing.
        image.put_u32(
            UDP_POOL + off::PORT_POOL_BITMAP + off::BITMAP_SIZE_OF_BITMAP,
            65_536,
        );
        image.put_u64(
            UDP_POOL + off::PORT_POOL_BITMAP + off::BITMAP_BUFFER,
            UDP_BITMAP_BUFFER,
        );

        let list_index = u64::from(port >> 8);
        let within = u64::from(port & 0xFF);
        image.put_u64(
            TCP_POOL + off::PORT_POOL_ASSIGNMENTS + list_index * 8,
            PORT_ASSIGNMENT,
        );
        image.put_u64(
            PORT_ASSIGNMENT + off::PORT_ASSIGNMENT_BIG_POOL_BASE,
            PORT_ASSIGNMENT_LIST,
        );
        // The entry points *inside* the listener, at its `Next` member, and the
        // low bits carry flags the walk has to mask off.
        let entry_at = PORT_ASSIGNMENT_LIST
            + within * off::PORT_ASSIGNMENT_ENTRY_STRIDE
            + off::PORT_ASSIGNMENT_ENTRY;
        image.put_u64(entry_at, (TCPL_A + off::TCPL_NEXT) | 0b11);

        for (at, next) in [(TCPL_A, Some(TCPL_B)), (TCPL_B, None)] {
            image.put_u64(at + off::TCPL_INETAF, INETAF_V4);
            image.put_u64(at + off::TCPL_OWNER, EPROCESS);
            image.put_u64(at + off::TCPL_CREATE_TIME, CREATE_TIME);
            image.put_port(at + off::TCPL_PORT, port);
            image.put_u64(
                at + off::TCPL_NEXT,
                next.map(|n| n + off::TCPL_NEXT).unwrap_or(0),
            );
        }
        image
    }

    fn walk(image: Image, with_partitions: bool, with_pools: bool) -> NetstatOutcome {
        let network = table(&windows_network_isf(false));
        let profile = profile(image.layer(), network, 10, Some(22000));
        let symbols = NetworkSymbols::from_profile(&profile).expect("a supported build");
        let tcpip = TcpipModule::new(TCPIP_BASE, table(&tcpip_isf(with_partitions, with_pools)));
        netstat(&profile, &symbols, &tcpip, &NetstatConfig::default())
            .expect("at least one half of the walk should run")
    }

    #[test]
    fn an_established_connection_is_reached_by_walking_the_partition_table() {
        let outcome = walk(partition_image(), true, false);
        assert!(outcome.partitions_walked);
        assert_eq!(outcome.partitions, 1);
        assert_eq!(outcome.endpoints.len(), 1, "{:?}", outcome.rejected);

        let row = &outcome.endpoints[0];
        assert_eq!(row.offset, TCPE);
        assert_eq!(row.protocol, Protocol::TcpV4);
        assert_eq!(row.local_address.as_deref(), Some("10.1.1.1"));
        assert_eq!(row.local_port, 443);
        assert_eq!(row.remote_address.as_deref(), Some("198.51.100.3"));
        assert_eq!(row.remote_port, Some(51_000));
        assert_eq!(row.owner_pid, Some(1234));
        assert_eq!(row.tag, "PartitionTable");
        assert!(matches!(row.state, SocketState::Tcp { value: 4, .. }));
    }

    #[test]
    fn a_walk_that_only_reached_half_the_tables_says_so_rather_than_looking_complete() {
        // The dangerous shape: every listening service and no established
        // connection reads exactly like an idle machine.
        let outcome = walk(partition_image(), true, false);
        assert!(!outcome.port_pools_walked);
        assert!(!outcome.is_complete());
        assert!(
            outcome
                .incomplete
                .iter()
                .any(|i| i.detail.contains("no listeners at all")),
            "{:?}",
            outcome.incomplete
        );
    }

    #[test]
    fn every_listener_on_one_port_is_followed_through_the_next_chain() {
        let outcome = walk(port_pool_image(445), false, true);
        assert!(outcome.port_pools_walked);
        assert_eq!(outcome.tcp_ports, 1);
        assert_eq!(outcome.udp_ports, 0);
        assert_eq!(outcome.endpoints.len(), 2, "{:?}", outcome.rejected);

        let addresses: Vec<u64> = outcome.endpoints.iter().map(|e| e.offset).collect();
        assert_eq!(addresses, vec![TCPL_A, TCPL_B]);
        for row in &outcome.endpoints {
            assert_eq!(row.local_port, 445);
            assert_eq!(row.state, SocketState::Listening);
            assert_eq!(row.tag, "TcpPortPool");
        }
    }

    #[test]
    fn the_flag_bits_in_a_stored_object_pointer_are_masked_before_it_is_followed() {
        // The fixture deliberately sets the low two bits. Without the mask the
        // walk lands three bytes into the listener and every member after it is
        // off by three — which decodes, and is wrong.
        assert_eq!(decode_pointer(0xFFFF_8000_1234_5673), 0xFFFF_8000_1234_5670);
        assert_eq!(decode_pointer(0), 0);
        let outcome = walk(port_pool_image(3389), false, true);
        assert_eq!(outcome.endpoints.len(), 2, "{:?}", outcome.rejected);
        assert_eq!(outcome.endpoints[0].offset, TCPL_A);
    }

    #[test]
    fn a_tcpip_build_without_the_symbols_says_which_ones_rather_than_returning_nothing() {
        let network = table(&windows_network_isf(false));
        let profile = profile(Image::new().layer(), network, 10, Some(22000));
        let symbols = NetworkSymbols::from_profile(&profile).expect("a supported build");
        let tcpip = TcpipModule::new(TCPIP_BASE, table(&tcpip_isf(false, false)));

        let err = netstat(&profile, &symbols, &tcpip, &NetstatConfig::default())
            .expect_err("neither half of the walk is possible");
        assert_eq!(err.class(), "unsupported_build");
        let text = err.to_string();
        assert!(text.contains("PartitionTable"), "{text}");
        assert!(text.contains("TcpPortPool"), "{text}");
    }

    /// Fatal is right — with no offset to the partition array there is no first
    /// partition to read — but what reaches the examiner has to name the stage
    /// that stopped and what stopping cost, not just that a member was unknown.
    ///
    /// The refusal travels to the examiner as the note that explains why this
    /// list holds no established connections, which is exactly the sentence
    /// that must not read like a machine that had none.
    #[test]
    fn a_partition_table_without_the_member_says_which_stage_stopped_and_what_it_cost() {
        let network = table(
            &windows_network_isf(false)
                .replace(r#""Partitions":"#, r#""PartitionsUnderAnotherName":"#),
        );
        let profile = profile(partition_image().layer(), network, 10, Some(22000));
        let symbols = NetworkSymbols::from_profile(&profile).expect("a supported build");
        let tcpip = TcpipModule::new(TCPIP_BASE, table(&tcpip_isf(true, false)));

        let err = netstat(&profile, &symbols, &tcpip, &NetstatConfig::default())
            .expect_err("neither half of the walk is possible");
        let text = err.to_string();
        assert!(text.contains("Partitions"), "{text}");
        assert!(text.contains(STAGE_NETWORK.key), "{text}");
        assert!(
            text.contains("no established TCP connection can be listed"),
            "the refusal must say what it cost: {text}"
        );
    }

    #[test]
    fn a_null_partition_table_pointer_is_reported_rather_than_walked() {
        // The port pools still resolve, so the walk returns rows. Without the
        // declaration, those listener rows would be read as the whole picture of
        // a machine that in fact had connections nobody could enumerate.
        let image = port_pool_image(445);
        let outcome = walk(image, true, true);
        assert!(outcome.port_pools_walked);
        assert!(!outcome.partitions_walked);
        assert!(!outcome.endpoints.is_empty());
        assert!(
            outcome
                .incomplete
                .iter()
                .any(|i| i.detail.contains("no established connections at all")),
            "{:?}",
            outcome.incomplete
        );
    }

    #[test]
    fn a_hash_table_whose_declared_size_is_really_an_address_is_capped_not_walked() {
        // Smeared acquisitions routinely leave an address in `TableSize`.
        // Walking it would be a hang; refusing it is a stated cap.
        let mut image = partition_image();
        image.put_u32(HASH_TABLE + off::HASH_TABLE_SIZE, 0x4000_0000);
        let outcome = walk(image, true, false);
        assert!(outcome.endpoints.is_empty());
        assert!(
            outcome
                .incomplete
                .iter()
                .any(|i| i.detail.contains("buckets, above the")),
            "{:?}",
            outcome.incomplete
        );
    }

    #[test]
    fn an_empty_hash_bucket_is_not_mistaken_for_an_endpoint() {
        // A `_LIST_ENTRY` head pointing at itself is an empty bucket. Treating
        // its `Flink` as an object would put a row at the directory's own
        // address, and that row would decode into nonsense.
        let outcome = walk(partition_image(), true, false);
        assert_eq!(outcome.endpoints.len(), 1);
        assert!(outcome.endpoints.iter().all(|e| e.offset != DIRECTORY));
    }

    #[test]
    fn bit_indices_are_absolute_across_a_chunked_bitmap_read() {
        // A chunk read at offset 4096 must yield ports from 32768 up. Dropping
        // the base would report every one of them as a low port.
        let mut ports = Vec::new();
        set_bit_indices(&[0b0000_0101], 0, &mut ports);
        assert_eq!(ports, vec![0, 2]);

        ports.clear();
        set_bit_indices(&[0b1000_0000], 4096, &mut ports);
        assert_eq!(ports, vec![32_775]);

        ports.clear();
        set_bit_indices(&[0, 0, 0], 10, &mut ports);
        assert!(ports.is_empty());
    }

    #[test]
    fn the_walk_reports_what_it_covered_in_a_form_a_report_can_carry() {
        let outcome = walk(port_pool_image(445), false, true);
        let json = outcome.to_json();
        assert_eq!(json["endpoint_count"], 2);
        assert_eq!(json["tcp_ports"], 1);
        assert_eq!(json["partitions_walked"], false);
        assert_eq!(json["port_pools_walked"], true);
        assert_eq!(json["complete"], false);
    }

    #[test]
    fn the_bounds_this_walk_runs_under_are_the_ones_it_documents() {
        let config = NetstatConfig::default();
        assert_eq!(config.max_partitions, MAX_PARTITIONS);
        assert_eq!(config.max_hash_buckets, MAX_HASH_BUCKETS);
        assert_eq!(config.max_bitmap_bytes, MAX_BITMAP_BYTES);
        assert_eq!(config.max_port_chain, MAX_PORT_CHAIN);
        // 8192 bytes is the real bitmap; the cap leaves room without admitting
        // an address that landed in the field.
        assert!(config.max_bitmap_bytes > 8192);
        assert!(config.max_bitmap_bytes < u64::from(u32::MAX));
    }
}
