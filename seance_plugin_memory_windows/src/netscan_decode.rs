//! Turning one validated network object into rows an examiner can read.
//!
//! Everything here is the second half of the sweep in [`super`]: the candidate
//! has already survived its pool header and its structural checks, and what
//! remains is reading fields out of it without inventing any.
//!
//! Three of those fields are where confident wrong answers come from, and each
//! is handled deliberately rather than idiomatically:
//!
//! * **Ports** are stored big-endian inside otherwise little-endian structures.
//!   The port reader takes the two bytes and interprets them big-endian whatever
//!   the symbol table declares, because network byte order is a property of
//!   tcpip.sys rather than of whoever wrote the ISF. Port 80 read the other way
//!   is 20480, which is a legal port number and therefore survives review.
//! * **Addresses** are two or three pointers away from the object, through a
//!   chain whose depth changed between builds. [`follow_to_struct`] walks the
//!   *symbol table's own* declared pointer chain instead of branching on a
//!   Windows version, so `_LOCAL_ADDRESS` (pointer to pointer to `_IN_ADDR`)
//!   and `_LOCAL_ADDRESS_WIN10_UDP` (pointer to `_IN_ADDR`) are both correct
//!   without either being special-cased.
//! * **The address family** decides whether the sixteen bytes at an `_IN_ADDR`
//!   are one IPv6 address or four bytes of IPv4 followed by twelve bytes of
//!   something else. There is no way to tell from the bytes, so a family value
//!   that is neither of Microsoft's two rejects the candidate rather than
//!   picking the more likely rendering.

// These test modules assert relationships between *compile-time constants* --
// MAX_SUBKEYS > MAX_INDEX_CELLS, MIN_CREATE_FILETIME < MAX_CREATE_FILETIME, a
// stage's declared record type. Clippy sees both sides are const and calls the
// assertion constant; that is exactly the point. They exist so that changing
// one bound in isolation fails, and deleting them would remove the guard rather
// than satisfy it.
#![allow(clippy::assertions_on_constants)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use seance_memory::object::{Obj, ObjError};
use seance_symbols::{Endian, SymbolTable, TypeId, TypeKind};

use super::{
    NetworkSymbols, ObjectKind, PoolTag, Readers, AF_INET, AF_INET6, MAX_POINTER_LEVELS,
    TYPE_EPROCESS, TYPE_IN_ADDR,
};

/// Earliest creation time this stage will believe, as a Windows FILETIME.
///
/// 1950-01-01T00:00:00Z. Below it the value is not a timestamp: it is an
/// unwritten field, a partially overwritten one, or four bytes of something
/// else. Rendering such a value produces a 1601 date beside a real IP address,
/// which reads as a fact about the machine.
pub const MIN_CREATE_FILETIME: u64 = 110_133_216_000_000_000;

/// Latest creation time this stage will believe, as a Windows FILETIME.
///
/// 2200-01-01T00:00:00Z. Same argument from the other end.
pub const MAX_CREATE_FILETIME: u64 = 189_025_920_000_000_000;

/// Longest process image name this stage will read out of an `_EPROCESS`.
///
/// `ImageFileName` is a fixed 15-byte array on every Windows build; the bound
/// exists so a symbol table declaring otherwise cannot turn one row into a
/// megabyte of "process name".
pub const MAX_PROCESS_NAME_BYTES: u64 = 256;

/// The IANA protocol number for TCP, as an `_ADDRESS_OBJECT` records it.
pub const IPPROTO_TCP: u16 = 6;

/// The IANA protocol number for UDP.
pub const IPPROTO_UDP: u16 = 17;

/// Which transport and which address family a row describes.
///
/// Kept as one value rather than two booleans because it is what a report
/// column shows, and because "TCPv4" and "TCPv6" are different findings about
/// what the machine was reachable over.
///
/// # Why there is a fifth and sixth variant
///
/// From Vista onwards tcpip.sys allocates a *different pool tag* per transport,
/// so a swept object is TCP or UDP by construction and nothing else can appear.
/// Windows XP's `_ADDRESS_OBJECT` instead carries the IANA protocol number in a
/// member, and a machine really does hold sockets that are neither: a raw socket
/// (protocol 255), an IPsec GRE binding (47), IGMP (2). Folding those into
/// `TcpV4` would report a sniffer's raw socket as a TCP service, and dropping
/// them would lose the single most suspicious row on the machine, so they are
/// carried as themselves with the number the image held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    /// TCP over IPv4.
    TcpV4,
    /// TCP over IPv6.
    TcpV6,
    /// UDP over IPv4.
    UdpV4,
    /// UDP over IPv6.
    UdpV6,
    /// An IPv4 socket whose transport is neither TCP nor UDP, carrying the IANA
    /// protocol number the object declared.
    OtherV4 {
        /// The IANA protocol number, exactly as the object held it.
        number: u16,
    },
    /// An IPv6 socket whose transport is neither TCP nor UDP.
    OtherV6 {
        /// The IANA protocol number, exactly as the object held it.
        number: u16,
    },
}

impl Protocol {
    /// The label Windows tooling uses, so a row can be compared against
    /// `netstat -ano` output without translation.
    ///
    /// A non-TCP, non-UDP socket has no such label, so it gets one that cannot
    /// be mistaken for a transport — the number itself travels in
    /// [`Protocol::ip_protocol`] and in the row's JSON rather than being folded
    /// into a name.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::TcpV4 => "TCPv4",
            Protocol::TcpV6 => "TCPv6",
            Protocol::UdpV4 => "UDPv4",
            Protocol::UdpV6 => "UDPv6",
            Protocol::OtherV4 { .. } => "IPv4",
            Protocol::OtherV6 { .. } => "IPv6",
        }
    }

    /// The IANA protocol number this row's transport has.
    ///
    /// On the record beside the label because "IPv4" alone does not say whether
    /// the socket was a raw one — which is a rootkit and sniffer indicator — or
    /// an ordinary multicast membership.
    pub fn ip_protocol(self) -> u16 {
        match self {
            Protocol::TcpV4 | Protocol::TcpV6 => IPPROTO_TCP,
            Protocol::UdpV4 | Protocol::UdpV6 => IPPROTO_UDP,
            Protocol::OtherV4 { number } | Protocol::OtherV6 { number } => number,
        }
    }

    /// The TCP protocol for an address family.
    fn tcp(v6: bool) -> Protocol {
        if v6 {
            Protocol::TcpV6
        } else {
            Protocol::TcpV4
        }
    }

    /// The UDP protocol for an address family.
    fn udp(v6: bool) -> Protocol {
        if v6 {
            Protocol::UdpV6
        } else {
            Protocol::UdpV4
        }
    }
}

/// The connection state a row carries.
///
/// A UDP socket has no state at all, and giving it one — even "CLOSED" — is a
/// claim about a connection that never existed. A listener's state is implied by
/// the object type rather than read from a field. Only a `_TCP_ENDPOINT` has a
/// state machine value, and only its symbol table can name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketState {
    /// A TCP endpoint's state-machine value, with the name the symbol table's
    /// enumeration gives it. `name` is `None` only when this build's table
    /// declares `State` as a plain integer, so no name exists to give.
    Tcp {
        /// The raw value, kept beside the name so a report can quote both.
        value: i128,
        /// The enumeration constant, when the table defines one.
        name: Option<String>,
    },
    /// A bound, listening socket. The object type is the state.
    Listening,
    /// UDP: connectionless, so there is no state.
    NotApplicable,
}

impl SocketState {
    /// What a report column shows.
    pub fn label(&self) -> String {
        match self {
            SocketState::Tcp {
                name: Some(name), ..
            } => name.clone(),
            SocketState::Tcp { value, name: None } => format!("state {value}"),
            SocketState::Listening => "LISTENING".to_string(),
            SocketState::NotApplicable => String::new(),
        }
    }
}

/// A creation time, kept in both the form the image held and the form a report
/// prints.
///
/// The raw FILETIME travels with the rendered string so that a disputed
/// timestamp can be re-derived from the number rather than from a formatted
/// date whose time zone somebody has to reconstruct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timestamp {
    /// 100 ns ticks since 1601-01-01, exactly as the object held it.
    pub filetime: u64,
    /// The same instant in RFC 3339, UTC.
    pub rfc3339: String,
}

/// One network endpoint, listener or socket, as an examiner reads it.
///
/// A dual-stack listener produces one of these per address family, because that
/// is genuinely how it is bound: reporting a single row would understate what
/// the machine was reachable on.
#[derive(Debug, Clone)]
pub struct NetworkEndpoint {
    /// Where the object starts, in the address space it was found in.
    pub offset: u64,
    /// The pool tag whose allocation it came out of.
    pub tag: &'static str,
    /// Which of the three network objects this is.
    pub kind: ObjectKind,
    /// Transport and address family.
    pub protocol: Protocol,
    /// The local address, or `None` when it could not be recovered. Never a
    /// wildcard substituted for an address that failed to read: a socket bound
    /// to everything and a socket whose binding could not be read are different
    /// findings.
    pub local_address: Option<String>,
    /// The local port, in host order.
    pub local_port: u16,
    /// The peer address. `None` for UDP, which is connectionless, and for a TCP
    /// endpoint whose address could not be recovered.
    pub remote_address: Option<String>,
    /// The peer port, in host order. `None` for UDP.
    pub remote_port: Option<u16>,
    /// Connection state.
    pub state: SocketState,
    /// PID of the owning process, when the `_EPROCESS` could be read.
    pub owner_pid: Option<u64>,
    /// Image name of the owning process, when it could be read.
    pub owner_process: Option<String>,
    /// When the object was created, when the value is believable.
    pub created: Option<Timestamp>,
    /// Everything that could not be read, and everything odd about the object.
    ///
    /// A row with notes is still evidence; a row whose gaps were silently filled
    /// in is not.
    pub notes: Vec<String>,
}

impl NetworkEndpoint {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "offset": self.offset,
            // Exact beside the number: this is where the allocation sits in the
            // space that was swept, above 2^53 in the kernel, and JSON numbers
            // are IEEE doubles — the numeric form can reach a client rounded by
            // up to a kilobyte.
            "offset_hex": format!("{:#x}", self.offset),
            "tag": self.tag,
            "kind": self.kind.as_str(),
            "protocol": self.protocol.as_str(),
            // The number, not only the name: "IPv4" beside protocol 255 is a raw
            // socket and beside 2 is an IGMP membership, and a report that shows
            // only the name cannot tell an examiner which it was looking at.
            "ip_protocol": self.protocol.ip_protocol(),
            "local_address": self.local_address,
            "local_port": self.local_port,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "state": self.state.label(),
            "owner_pid": self.owner_pid,
            "owner_process": self.owner_process,
            "created": self.created.as_ref().map(|t| t.rfc3339.clone()),
            "created_filetime": self.created.as_ref().map(|t| t.filetime),
            "notes": self.notes,
        })
    }
}

/// Decode one validated candidate into rows, or say why it is not one.
///
/// `Err` is a *rejection*, not a failure: the address held four bytes that
/// matched a pool tag and nothing else about it holds up. The caller counts
/// those; it does not abandon the sweep.
pub(crate) fn decode(
    readers: &Readers,
    _symbols: &NetworkSymbols,
    tag: PoolTag,
    address: u64,
    mut notes: Vec<String>,
) -> Result<Vec<NetworkEndpoint>, String> {
    // Windows XP's two objects reach rows through
    // [`crate::netscan::legacy`], which reads a protocol number and two inline
    // addresses rather than an `_INETAF` and a pointer chain. Naming them here
    // rather than leaving a catch-all arm means a future caller that routes one
    // to the wrong decoder is refused instead of decoding an `_ADDRESS_OBJECT`
    // at `_TCP_ENDPOINT`'s offsets — which produces a full row of plausible
    // nonsense.
    if matches!(tag.kind, ObjectKind::AddressObject | ObjectKind::TcptObject) {
        return Err(wrong_decoder(tag.kind));
    }

    let type_name = tag.kind.type_name();
    let object = readers
        .network
        .object(address, type_name)
        .map_err(|err| format!("'{type_name}' could not be built at {address:#x}: {err}"))?;

    let family = address_family(&object)?;
    let v6 = family == AF_INET6;

    let (owner_pid, owner_process) = read_owner(readers, &object, &mut notes);
    let created = read_create_time(&object, &mut notes);

    match tag.kind {
        ObjectKind::TcpEndpoint => {
            let state = read_tcp_state(&object)?;
            let local_port = read_port(&object, "LocalPort")?;
            let remote_port = read_port(&object, "RemotePort")?;

            let addr_info = follow_to_struct(&object, "AddrInfo")
                .map_err(|err| format!("'AddrInfo' could not be followed: {err}"))?;
            let (local_address, remote_address) = match &addr_info {
                Some(info) => {
                    let local = follow_to_struct(info, "Local")
                        .ok()
                        .flatten()
                        .and_then(|local| follow_to_struct(&local, "pData").ok().flatten())
                        .and_then(|in_addr| render(&in_addr, v6).ok());
                    let remote = follow_to_struct(info, "Remote")
                        .ok()
                        .flatten()
                        .and_then(|in_addr| render(&in_addr, v6).ok());
                    (local, remote)
                }
                None => (None, None),
            };
            if addr_info.is_none() {
                notes.push(
                    "'AddrInfo' is null, so neither endpoint address could be recovered"
                        .to_string(),
                );
            }
            if local_address.is_none() {
                notes.push("the local address could not be recovered".to_string());
            }
            if remote_address.is_none() {
                notes.push("the remote address could not be recovered".to_string());
            }

            // Upstream's own last-resort check, and a good one: an endpoint with
            // no readable local address is only believable if it names a
            // plausible owning process. Without either, four bytes matched a tag
            // and nothing else about the candidate stands up.
            if local_address.is_none() && !plausible_owner(owner_pid) {
                return Err(format!(
                    "neither a local address nor a plausible owning process could be read \
                     (PID {owner_pid:?})"
                ));
            }

            Ok(vec![NetworkEndpoint {
                offset: address,
                tag: tag.tag,
                kind: tag.kind,
                protocol: Protocol::tcp(v6),
                local_address,
                local_port,
                remote_address,
                remote_port: Some(remote_port),
                state,
                owner_pid,
                owner_process,
                created,
                notes,
            }])
        }
        ObjectKind::TcpListener | ObjectKind::UdpEndpoint => {
            let port = read_port(&object, "Port")?;
            let binding = local_binding(&object);
            let bindings = dual_stack_sockets(family, binding, &mut notes);
            let is_udp = tag.kind == ObjectKind::UdpEndpoint;

            let mut rows = Vec::with_capacity(bindings.len());
            for binding in bindings {
                rows.push(NetworkEndpoint {
                    offset: address,
                    tag: tag.tag,
                    kind: tag.kind,
                    protocol: if is_udp {
                        Protocol::udp(binding.v6)
                    } else {
                        Protocol::tcp(binding.v6)
                    },
                    local_address: binding.local.clone(),
                    local_port: port,
                    // A listener's peer really is the unspecified address until
                    // a client connects, at which point tcpip.sys creates a
                    // separate `_TCP_ENDPOINT` carrying the peer. UDP has no
                    // peer at all.
                    remote_address: if is_udp {
                        None
                    } else {
                        Some(binding.remote.clone())
                    },
                    remote_port: if is_udp { None } else { Some(0) },
                    state: if is_udp {
                        SocketState::NotApplicable
                    } else {
                        SocketState::Listening
                    },
                    owner_pid,
                    owner_process: owner_process.clone(),
                    created: created.clone(),
                    notes: notes.clone(),
                });
            }
            Ok(rows)
        }
        // Unreachable through the guard above, and written out rather than left
        // to a catch-all so that adding a seventh object kind is a compile
        // error here instead of a silent misdecode.
        ObjectKind::AddressObject | ObjectKind::TcptObject => Err(wrong_decoder(tag.kind)),
    }
}

/// The refusal for an object routed to the decoder that does not describe it.
///
/// Both directions of that mistake read a real structure at another structure's
/// offsets, which is the failure mode this whole module is arranged to prevent,
/// so it is a refusal naming both rather than a best effort.
fn wrong_decoder(kind: ObjectKind) -> String {
    format!(
        "'{}' is one of Windows XP's tcpip.sys objects and has none of the members this decoder \
         reads; it is decoded by the legacy stage instead",
        kind.type_name()
    )
}

/// The address family this object's `_INETAF` declares.
///
/// A value that is neither of Microsoft's two rejects the candidate. It is the
/// single most discriminating semantic test available here, and getting it wrong
/// in the permissive direction means rendering sixteen bytes of an IPv6 address
/// as a dotted quad, or four bytes of IPv4 padded with twelve bytes of adjacent
/// memory as an IPv6 address.
fn address_family(object: &Obj) -> Result<u64, String> {
    let inet_af = follow_to_struct(object, "InetAF")
        .map_err(|err| format!("'InetAF' could not be followed: {err}"))?
        .ok_or_else(|| "'InetAF' is null, so the address family is unknown".to_string())?;
    let family = inet_af
        .int("AddressFamily")
        .map_err(|err| format!("'_INETAF.AddressFamily' could not be read: {err}"))?
        .as_u64()
        .ok_or_else(|| "'_INETAF.AddressFamily' is negative".to_string())?;
    if family != AF_INET && family != AF_INET6 {
        return Err(format!(
            "the address family is {family}, and Windows uses {AF_INET} (AF_INET) or {AF_INET6} \
             (AF_INET6)"
        ));
    }
    Ok(family)
}

/// A TCP endpoint's state, validated against the symbol table's own
/// enumeration.
///
/// A value the enumeration does not define is a rejection: tcpip's state machine
/// has twelve values, so a candidate holding 47 there is not an endpoint. Where
/// the table declares `State` as a plain integer there is nothing to validate
/// against, and the value is carried unnamed rather than given an invented
/// label.
fn read_tcp_state(object: &Obj) -> Result<SocketState, String> {
    let table = object.reader().symbols();
    let type_name = object.type_name();
    let member = table
        .member(type_name, "State")
        .map_err(|err| format!("'{type_name}.State' could not be resolved: {err}"))?;
    let member_ty = member.ty;
    let value = object
        .int("State")
        .map_err(|err| format!("'{type_name}.State' could not be read: {err}"))?
        .as_i128();

    let entry = table
        .entry(member_ty)
        .map_err(|err| format!("'{type_name}.State' has an unreadable type: {err}"))?;
    match &entry.kind {
        TypeKind::Enum(info) => match info.name_of(value) {
            Some(name) => Ok(SocketState::Tcp {
                value,
                name: Some(name.to_string()),
            }),
            None => Err(format!(
                "the TCP state {value} is not a value this build's TCPStateEnum defines"
            )),
        },
        _ => Ok(SocketState::Tcp { value, name: None }),
    }
}

/// Read a port member and byte-swap it into host order.
///
/// The member's *width* comes from the symbol table, because a build that made
/// the field something other than two bytes is a build this code has not been
/// taught. The member's *byte order* does not: tcpip.sys stores ports in network
/// byte order regardless of what the ISF's author declared, and a table that
/// declares them little-endian would otherwise turn port 80 into 20480 — a legal
/// ephemeral port, indistinguishable from a real answer in a report.
pub(crate) fn read_port(object: &Obj, member: &str) -> Result<u16, String> {
    let type_name = object.type_name();
    let table = object.reader().symbols();
    let declared = table
        .member(type_name, member)
        .map_err(|err| format!("'{type_name}.{member}' could not be resolved: {err}"))?
        .ty;
    let width = table
        .size_of_id(declared)
        .map_err(|err| format!("'{type_name}.{member}' has no computable width: {err}"))?;
    if width != 2 {
        return Err(format!(
            "'{type_name}.{member}' is declared {width} byte(s) wide, and a TCP or UDP port is \
             two"
        ));
    }
    let address = object
        .member_address(member)
        .map_err(|err| format!("'{type_name}.{member}' has no address: {err}"))?;
    let bytes = object
        .reader()
        .read_bytes(address, 2)
        .map_err(|err| format!("'{type_name}.{member}' could not be read: {err}"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// The owning process's PID and image name, or nothing plus a note.
///
/// Never a guess. A network object whose owner cannot be resolved is still
/// evidence of a connection; attributing it to the wrong process would not be.
fn read_owner(
    readers: &Readers,
    object: &Obj,
    notes: &mut Vec<String>,
) -> (Option<u64>, Option<String>) {
    let pointer = match object.pointer("Owner") {
        Ok(pointer) => pointer,
        Err(err) => {
            notes.push(format!("the 'Owner' pointer could not be read: {err}"));
            return (None, None);
        }
    };
    if pointer == 0 {
        notes.push(
            "the 'Owner' pointer is null, so no owning process is recorded in this object"
                .to_string(),
        );
        return (None, None);
    }

    let process = match readers.kernel.object(pointer, TYPE_EPROCESS) {
        Ok(process) => process,
        Err(err) => {
            notes.push(format!(
                "the owning '{TYPE_EPROCESS}' at {pointer:#x} could not be built: {err}"
            ));
            return (None, None);
        }
    };

    let pid = match process.int("UniqueProcessId") {
        Ok(value) => match value.as_u64() {
            Some(pid) => Some(pid),
            None => {
                notes.push(format!(
                    "the owning process at {pointer:#x} reports a negative PID"
                ));
                None
            }
        },
        Err(err) => {
            notes.push(format!(
                "the owning process at {pointer:#x} could not be read: {err}"
            ));
            None
        }
    };

    let name = match read_process_name(&process) {
        Ok(name) => name,
        Err(err) => {
            notes.push(format!(
                "the owning process name at {pointer:#x} could not be read: {err}"
            ));
            None
        }
    };

    (pid, name)
}

/// `ImageFileName` as text, trimmed at its first NUL.
///
/// The bytes are returned exactly as acquired by the object model; the trimming
/// and the lossy decode happen here so the decision is visible. A name with
/// bytes that are not valid UTF-8 keeps replacement characters rather than being
/// dropped: a process called `sv?host.exe` is a finding.
fn read_process_name(process: &Obj) -> Result<Option<String>, ObjError> {
    let count = process.array_len_capped("ImageFileName", MAX_PROCESS_NAME_BYTES)?;
    if count == 0 {
        return Ok(None);
    }
    let bytes = process.bytes("ImageFileName")?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&bytes[..end]).into_owned()))
}

/// The object's creation time, if the value is believable.
///
/// A FILETIME outside 1950–2200 is not a time this machine recorded: it is an
/// unwritten field or four bytes of something else. Omitting it and saying so is
/// the only honest handling, because a 1601 timestamp printed beside a real IP
/// address reads as a fact.
pub(crate) fn read_create_time(object: &Obj, notes: &mut Vec<String>) -> Option<Timestamp> {
    let type_name = object.type_name();
    // `CreateTime` is a `_LARGE_INTEGER` union on every build seen, but a table
    // that declares it as a plain 64-bit integer is equally readable, and asking
    // the table which it is beats assuming either.
    let raw = if object.has_member("CreateTime") && has_quad_part(object) {
        object.int("CreateTime.QuadPart")
    } else {
        object.int("CreateTime")
    };
    let value = match raw {
        Ok(value) => value,
        Err(err) => {
            notes.push(format!("'{type_name}.CreateTime' could not be read: {err}"));
            return None;
        }
    };
    let Some(filetime) = value.as_u64() else {
        notes.push(format!(
            "the creation time in '{type_name}' is negative, so it is not a timestamp"
        ));
        return None;
    };
    if !(MIN_CREATE_FILETIME..=MAX_CREATE_FILETIME).contains(&filetime) {
        notes.push(format!(
            "the creation time {filetime} lies outside 1950-2200, so it is not a time this \
             machine recorded"
        ));
        return None;
    }
    match seance_core::time::filetime_to_rfc3339(filetime) {
        Some(rfc3339) => Some(Timestamp { filetime, rfc3339 }),
        None => {
            notes.push(format!(
                "the creation time {filetime} could not be converted to a wall-clock time"
            ));
            None
        }
    }
}

/// Whether `CreateTime` is an aggregate carrying a `QuadPart`.
fn has_quad_part(object: &Obj) -> bool {
    object
        .embedded("CreateTime")
        .map(|inner| inner.has_member("QuadPart"))
        .unwrap_or(false)
}

/// Whether a PID is one Windows plausibly issued.
///
/// Deliberately the same bound upstream applies, so that the two tools accept
/// and reject the same candidates and a difference between their outputs is a
/// difference in the analysis rather than in a threshold. It is a heuristic and
/// not a rule: Windows PIDs are multiples of four but a long-uptime machine does
/// issue values above 65,535, so this is only ever consulted as a last resort,
/// for a candidate whose local address could not be read at all. Widening it
/// would admit four bytes of adjacent memory as an owning process.
pub(crate) fn plausible_owner(pid: Option<u64>) -> bool {
    matches!(pid, Some(pid) if pid > 0 && pid <= 65_535)
}

/// What a listener's or UDP socket's `LocalAddr` chain said.
///
/// Three outcomes, and collapsing any two of them loses a finding. "Bound to
/// everything" and "we could not read what it was bound to" in particular must
/// never render the same, because the first is a wide-open service and the
/// second is a gap in the evidence.
enum LocalBinding {
    /// The socket is bound to the address in this `_IN_ADDR`.
    Bound(Obj),
    /// `LocalAddr` is null: the socket is bound to every address of its family.
    Unbound,
    /// The pointer chain could not be followed.
    Unreadable(String),
}

/// Follow `LocalAddr` down to the `_IN_ADDR` a socket is bound to.
fn local_binding(object: &Obj) -> LocalBinding {
    let local = match follow_to_struct(object, "LocalAddr") {
        Ok(Some(local)) => local,
        Ok(None) => return LocalBinding::Unbound,
        Err(err) => return LocalBinding::Unreadable(format!("'LocalAddr': {err}")),
    };
    match follow_to_struct(&local, "pData") {
        Ok(Some(in_addr)) => LocalBinding::Bound(in_addr),
        // A `_LOCAL_ADDRESS` whose `pData` is null carries no address, which is
        // the same fact as an absent `_LOCAL_ADDRESS`.
        Ok(None) => LocalBinding::Unbound,
        Err(err) => LocalBinding::Unreadable(format!("'{}.pData': {err}", local.type_name())),
    }
}

/// One address family a socket is bound on.
struct Binding {
    /// Whether this binding is IPv6.
    v6: bool,
    /// The local address, or `None` when it could not be recovered.
    local: Option<String>,
    /// The peer address, which for a listener is always the unspecified one.
    remote: String,
}

/// How a listener or UDP socket is actually bound.
///
/// A Windows socket opened `AF_INET6` and bound to no particular address accepts
/// **both** IPv4 and IPv6 traffic, and reporting one row for it would understate
/// what the machine was reachable on. A socket bound to a specific address is
/// reachable only on that address's family, and gets one row.
///
/// A binding that could not be read yields one row with no local address and a
/// note, never a wildcard: reporting a service as listening on every address
/// when the evidence did not say so is the more damaging of the two errors.
fn dual_stack_sockets(family: u64, binding: LocalBinding, notes: &mut Vec<String>) -> Vec<Binding> {
    let v6 = family == AF_INET6;
    match binding {
        LocalBinding::Bound(in_addr) => match render(&in_addr, v6) {
            Ok(local) => vec![Binding {
                v6,
                local: Some(local),
                remote: unspecified(v6),
            }],
            Err(detail) => {
                notes.push(format!(
                    "the bound local address could not be read: {detail}"
                ));
                vec![Binding {
                    v6,
                    local: None,
                    remote: unspecified(v6),
                }]
            }
        },
        LocalBinding::Unreadable(detail) => {
            notes.push(format!(
                "the local address could not be reached, so whether this socket was bound to one \
                 address or to all of them is unknown: {detail}"
            ));
            vec![Binding {
                v6,
                local: None,
                remote: unspecified(v6),
            }]
        }
        LocalBinding::Unbound => {
            let mut bindings = vec![Binding {
                v6: false,
                local: Some(unspecified(false)),
                remote: unspecified(false),
            }];
            if v6 {
                bindings.push(Binding {
                    v6: true,
                    local: Some(unspecified(true)),
                    remote: unspecified(true),
                });
            }
            bindings
        }
    }
}

/// The unspecified address of a family: `0.0.0.0` or `::`.
fn unspecified(v6: bool) -> String {
    if v6 {
        Ipv6Addr::UNSPECIFIED.to_string()
    } else {
        Ipv4Addr::UNSPECIFIED.to_string()
    }
}

/// Render an `_IN_ADDR` as the family says it should be rendered.
///
/// The two members overlap in memory: `addr4` is the first four bytes and
/// `addr6` all sixteen. Choosing by family rather than by content is not a
/// convenience — there is no content-based way to tell them apart, and both
/// wrong renderings produce a legal-looking address.
fn render(in_addr: &Obj, v6: bool) -> Result<String, String> {
    if v6 {
        let bytes = in_addr
            .bytes("addr6")
            .map_err(|err| format!("'{TYPE_IN_ADDR}.addr6' could not be read: {err}"))?;
        format_ipv6(&bytes)
    } else {
        let bytes = in_addr
            .bytes("addr4")
            .map_err(|err| format!("'{TYPE_IN_ADDR}.addr4' could not be read: {err}"))?;
        format_ipv4(&bytes)
    }
}

/// Four bytes as a dotted quad.
pub fn format_ipv4(bytes: &[u8]) -> Result<String, String> {
    let octets: [u8; 4] = bytes.try_into().map_err(|_| {
        format!(
            "an IPv4 address is four bytes and this member is {}",
            bytes.len()
        )
    })?;
    Ok(Ipv4Addr::from(octets).to_string())
}

/// Sixteen bytes as an RFC 5952 IPv6 address.
///
/// The zero-run compression matters for comparability: `fe80:0:0:0:0:0:0:1` and
/// `fe80::1` are the same address, and only one of them matches what the rest of
/// an investigation will have written down.
pub fn format_ipv6(bytes: &[u8]) -> Result<String, String> {
    let octets: [u8; 16] = bytes.try_into().map_err(|_| {
        format!(
            "an IPv6 address is sixteen bytes and this member is {}",
            bytes.len()
        )
    })?;
    Ok(Ipv6Addr::from(octets).to_string())
}

/// Follow a pointer member down to the structure it eventually reaches,
/// however many levels of indirection the symbol table declares.
///
/// # Why this is not [`Obj::follow`]
///
/// `_LOCAL_ADDRESS.pData` is a pointer *to a pointer* to an `_IN_ADDR` on most
/// builds, and `_LOCAL_ADDRESS_WIN10_UDP.pData` is a pointer directly to one.
/// Both are declared exactly that way in the symbol table, so walking the
/// declared chain gets both right, while branching on a Windows version gets one
/// of them wrong on any build whose classification is off by one. A wrong
/// indirection depth does not fail: it reads an address out of whatever the
/// first eight bytes of the `_IN_ADDR` happen to be.
///
/// The first read happens in the object's own space and every later one in the
/// native space, because a pool candidate's bytes may have come from physical
/// memory while the pointers inside it are kernel virtual addresses.
///
/// `Ok(None)` for a null pointer anywhere in the chain: a socket bound to no
/// particular address has a null `LocalAddr`, and that is a fact rather than a
/// failure.
///
/// # Errors
///
/// [`ObjError::Symbols`] when the member is not a pointer, when the chain ends
/// in something that is not a structure, or when it ends in a type declared in a
/// symbol table this analysis does not have. [`ObjError::Cap`] when the chain is
/// longer than [`MAX_POINTER_LEVELS`], which means the table refers to itself.
pub fn follow_to_struct(object: &Obj, member: &str) -> Result<Option<Obj>, ObjError> {
    let table: Arc<SymbolTable> = Arc::clone(object.reader().symbols());
    let owner = object.type_name().to_string();
    let what = format!("{owner}.{member}");

    let mut ty = table.member(&owner, member)?.ty;
    let mut address = object.member_address(member)?;
    let mut reader = object.reader().clone();

    for level in 0..=MAX_POINTER_LEVELS {
        match hop(&table, ty, &what)? {
            Hop::Deref {
                size,
                endian,
                subtype,
            } => {
                let value = read_pointer(&reader, address, size, endian, &what)?;
                if value == 0 {
                    return Ok(None);
                }
                address = value;
                ty = subtype;
                reader = reader.in_native_space();
            }
            Hop::Land { name } => {
                if level == 0 {
                    return Err(seance_symbols::SymbolError::WrongTypeKind {
                        name: what,
                        actual: "a structure member",
                        expected: "a pointer member",
                    }
                    .into());
                }
                return Ok(Some(reader.object(address, &name)?));
            }
            Hop::Refuse { detail } => {
                return Err(seance_symbols::SymbolError::malformed(format!(
                    "'{what}' cannot be followed to a structure: {detail}"
                ))
                .into())
            }
        }
    }

    Err(ObjError::Cap {
        what: "pointer indirections in a member chain",
        cap: u64::from(MAX_POINTER_LEVELS),
    })
}

/// The address a member designates: the value it holds if it is a pointer, or
/// its own address if it is embedded.
///
/// tcpip's structures reach the kernel's types both ways depending on the build
/// — `_PARTITION.Endpoints` is a *pointer* to an `_RTL_DYNAMIC_HASH_TABLE` while
/// `_INET_PORT_POOL.PortBitMap` is an `_RTL_BITMAP` *inside* the pool — and both
/// of those types are declared in the kernel's symbol table rather than the
/// tcpip one, so neither can be reached with [`Obj::follow`]. Asking the table
/// which shape this build uses is the only way that is right on both.
///
/// `Ok(None)` for a null pointer.
pub(crate) fn target_address(object: &Obj, member: &str) -> Result<Option<u64>, ObjError> {
    let table: Arc<SymbolTable> = Arc::clone(object.reader().symbols());
    let owner = object.type_name().to_string();
    let what = format!("{owner}.{member}");
    let ty = table.member(&owner, member)?.ty;
    let address = object.member_address(member)?;

    let (size, endian) = match &table.entry(ty)?.kind {
        TypeKind::Pointer { size, endian, .. } => (*size, *endian),
        // Embedded: the member's bytes are here, whatever its type resolves to.
        _ => return Ok(Some(address)),
    };
    let value = read_pointer(object.reader(), address, size, endian, &what)?;
    Ok(if value == 0 { None } else { Some(value) })
}

/// One step of a pointer chain, taken out of the symbol table as owned data so
/// nothing borrows the table across a read.
enum Hop {
    /// A pointer: dereference it at this width and byte order.
    Deref {
        size: u64,
        endian: Endian,
        subtype: TypeId,
    },
    /// A structure: the chain ends here.
    Land { name: String },
    /// Neither, and following it further would be a guess.
    Refuse { detail: String },
}

/// Classify what a type id is, for the purposes of a pointer walk.
fn hop(table: &SymbolTable, ty: TypeId, what: &str) -> Result<Hop, ObjError> {
    let entry = table.entry(ty)?;
    Ok(match &entry.kind {
        TypeKind::Pointer {
            size,
            endian,
            subtype,
        } => Hop::Deref {
            size: *size,
            endian: *endian,
            subtype: *subtype,
        },
        TypeKind::Aggregate(_) => Hop::Land {
            name: entry.name.to_string(),
        },
        TypeKind::Unresolved {
            table: other,
            name: reference,
        } => Hop::Refuse {
            detail: match other {
                Some(other) => format!(
                    "it ends in '{other}!{reference}', a type declared in a symbol table this \
                     analysis was not given"
                ),
                None => {
                    format!("it ends in '{reference}', which this symbol table does not define")
                }
            },
        },
        other => Hop::Refuse {
            detail: format!(
                "'{what}' resolves through {}, which is neither a pointer nor a structure",
                other.as_str()
            ),
        },
    })
}

/// Read a pointer of an explicitly declared width and byte order.
///
/// Deliberately not [`seance_memory::object::StructReader::read_pointer_at`],
/// which uses the ISF's generic `pointer` base type: a member's own pointer type
/// carries its own width, and honouring it is what keeps a 32-bit structure
/// readable through a table that also describes 64-bit ones.
fn read_pointer(
    reader: &seance_memory::object::StructReader,
    address: u64,
    size: u64,
    endian: Endian,
    what: &str,
) -> Result<u64, ObjError> {
    if size != 4 && size != 8 {
        return Err(ObjError::PointerWidth {
            what: what.to_string(),
            size,
        });
    }
    let bytes = reader.read_bytes(address, size)?;
    let mut raw = 0u64;
    match endian {
        Endian::Little => {
            for &byte in bytes.iter().rev() {
                raw = (raw << 8) | u64::from(byte);
            }
        }
        Endian::Big => {
            for &byte in bytes.iter() {
                raw = (raw << 8) | u64::from(byte);
            }
        }
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_bytes_render_as_a_dotted_quad_and_anything_else_is_refused() {
        assert_eq!(format_ipv4(&[192, 168, 0, 1]).unwrap(), "192.168.0.1");
        assert_eq!(format_ipv4(&[0, 0, 0, 0]).unwrap(), "0.0.0.0");
        let err = format_ipv4(&[1, 2, 3]).expect_err("three bytes are not an address");
        assert!(err.contains("four bytes"), "{err}");
    }

    #[test]
    fn sixteen_bytes_render_as_a_compressed_ipv6_address() {
        // RFC 5952 form, so a row matches what the rest of an investigation
        // wrote down rather than an expanded variant of the same address.
        let bytes = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        assert_eq!(format_ipv6(&bytes).unwrap(), "2001:db8::1");
        assert_eq!(format_ipv6(&[0u8; 16]).unwrap(), "::");
        let err = format_ipv6(&[0u8; 4]).expect_err("four bytes are not an IPv6 address");
        assert!(err.contains("sixteen bytes"), "{err}");
    }

    #[test]
    fn an_ipv6_address_is_never_shortened_into_something_that_reads_as_ipv4() {
        // The four bytes at the front of this address are 10.0.0.1, which is a
        // perfectly plausible private IPv4 address that the machine never used.
        let bytes = [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let rendered = format_ipv6(&bytes).unwrap();
        assert_ne!(rendered, "10.0.0.1");
        assert!(rendered.contains(':'), "{rendered}");
    }

    #[test]
    fn the_unspecified_address_of_each_family_is_the_one_windows_shows() {
        assert_eq!(unspecified(false), "0.0.0.0");
        assert_eq!(unspecified(true), "::");
    }

    #[test]
    fn a_pid_outside_the_range_windows_issues_is_not_a_plausible_owner() {
        assert!(plausible_owner(Some(4)));
        assert!(plausible_owner(Some(65_535)));
        assert!(!plausible_owner(Some(0)));
        assert!(!plausible_owner(Some(65_536)));
        assert!(!plausible_owner(None));
    }

    #[test]
    fn the_believable_creation_time_window_is_the_one_it_claims_to_be() {
        // Derived rather than copied: 1950-01-01 is 631,152,000 seconds before
        // the Unix epoch, and a FILETIME is 100 ns ticks from 1601-01-01.
        let epoch_gap = 11_644_473_600u64;
        assert_eq!(MIN_CREATE_FILETIME, (epoch_gap - 631_152_000) * 10_000_000);
        assert_eq!(
            MAX_CREATE_FILETIME,
            (epoch_gap + 7_258_118_400) * 10_000_000
        );
        assert!(MIN_CREATE_FILETIME < MAX_CREATE_FILETIME);
        // A 2021 timestamp is inside the window; an unwritten field is not.
        assert!((MIN_CREATE_FILETIME..=MAX_CREATE_FILETIME).contains(&132_669_792_000_000_000));
        assert!(!(MIN_CREATE_FILETIME..=MAX_CREATE_FILETIME).contains(&0));
        assert!(!(MIN_CREATE_FILETIME..=MAX_CREATE_FILETIME).contains(&1));
    }

    #[test]
    fn protocol_labels_match_what_windows_tooling_prints() {
        assert_eq!(Protocol::TcpV4.as_str(), "TCPv4");
        assert_eq!(Protocol::TcpV6.as_str(), "TCPv6");
        assert_eq!(Protocol::UdpV4.as_str(), "UDPv4");
        assert_eq!(Protocol::UdpV6.as_str(), "UDPv6");
        assert_eq!(Protocol::tcp(true), Protocol::TcpV6);
        assert_eq!(Protocol::udp(false), Protocol::UdpV4);
    }

    #[test]
    fn a_udp_socket_is_never_labelled_with_a_tcp_state() {
        assert_eq!(SocketState::NotApplicable.label(), "");
        assert_eq!(SocketState::Listening.label(), "LISTENING");
        assert_eq!(
            SocketState::Tcp {
                value: 4,
                name: Some("ESTABLISHED".into())
            }
            .label(),
            "ESTABLISHED"
        );
        // An unnamed state says so rather than borrowing a neighbouring label.
        assert_eq!(
            SocketState::Tcp {
                value: 11,
                name: None
            }
            .label(),
            "state 11"
        );
    }

    #[test]
    fn an_unbound_dual_stack_socket_yields_a_row_for_each_family_it_accepts() {
        let mut notes = Vec::new();
        let unbound_v4 = dual_stack_sockets(AF_INET, LocalBinding::Unbound, &mut notes);
        assert_eq!(unbound_v4.len(), 1);
        assert_eq!(unbound_v4[0].local.as_deref(), Some("0.0.0.0"));
        assert!(!unbound_v4[0].v6);

        let unbound_v6 = dual_stack_sockets(AF_INET6, LocalBinding::Unbound, &mut notes);
        assert_eq!(
            unbound_v6.len(),
            2,
            "an AF_INET6 socket bound to nothing accepts IPv4 as well"
        );
        assert_eq!(unbound_v6[0].local.as_deref(), Some("0.0.0.0"));
        assert_eq!(unbound_v6[1].local.as_deref(), Some("::"));
        assert!(notes.is_empty(), "an unbound socket is a fact, not a gap");
    }

    #[test]
    fn a_binding_that_could_not_be_read_is_never_reported_as_bound_to_everything() {
        // The dangerous collapse: "we could not read what this service was
        // listening on" rendered as "it was listening on every address".
        let mut notes = Vec::new();
        let rows = dual_stack_sockets(
            AF_INET6,
            LocalBinding::Unreadable("the page was never acquired".into()),
            &mut notes,
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].local, None);
        assert!(rows[0].v6);
        assert_eq!(rows[0].remote, "::");
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("unknown"), "{}", notes[0]);
    }
}
