//! Each process's network sockets, walked from its open files.
//!
//! At parity with Volatility 3's `linux.sockstat`. A socket is an open file whose
//! inode is a socket inode, so this reuses the [`crate::lsof`] fd-table walk and,
//! for each descriptor, asks whether the file behind it is a socket. When it is,
//! it recovers the `struct socket`/`struct sock` behind the inode and reports the
//! endpoint: address family, socket type, protocol, connection state, and — for
//! `AF_INET` — the source and destination address and port.
//!
//! ## How a file becomes a socket
//!
//! `file → f_path.dentry → d_inode`, and `S_ISSOCK(inode.i_mode)` is the gate.
//! Volatility tests the file's `f_op` against the `socket_file_ops` /
//! `sockfs_dentry_operations` symbols; this uses the structural inode-mode test
//! instead, which needs no extra symbols and is stated on the record
//! (`socket_gate`). A socket inode is embedded in a `socket_alloc`, so the socket
//! is `container_of(inode, socket_alloc, vfs_inode)` — the inode's address minus
//! the offset of `vfs_inode`, bounds-checked.
//!
//! ## Scope, stated on the record
//!
//! `AF_INET` addresses and ports are decoded (dotted-quad from the raw
//! network-order bytes; ports converted to host order). Non-INET families
//! (`AF_UNIX`, `AF_NETLINK`, `AF_PACKET`, …) report family, type and state with
//! [`Field::NotApplicable`] addresses. IPv6 `sock_common` addresses do not exist
//! before Linux 3.13 and appear as [`Field::NotDeclared`] on such kernels — an
//! answer, never a blank.

use seance_core::io::IncompleteReason;
use seance_memory::binding::{BuildBinding, Field, MemberSet, MemberSpec, TypeSpec};
use seance_memory::meta::Incomplete;
use seance_memory::object::{Obj, StructReader};

use crate::error::StageError;
use crate::lsof::MAX_FDS_PER_TASK;
use crate::module::STAGE_LINUX_NETWORK_SOCKETS;
use crate::profile::LinuxProfile;
use crate::read::signed_to_json;
use crate::tasks::TaskList;

/// `S_IFMT` mask and the `S_IFSOCK` value: `(i_mode & 0xF000) == 0xC000`.
const S_IFMT: u64 = 0xF000;
const S_IFSOCK: u64 = 0xC000;

/// Address families, indexed by `skc_family`.
fn family_name(value: u64) -> Option<&'static str> {
    Some(match value {
        1 => "AF_UNIX",
        2 => "AF_INET",
        10 => "AF_INET6",
        16 => "AF_NETLINK",
        17 => "AF_PACKET",
        _ => return None,
    })
}

const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;

/// Socket types, indexed by `sk_type`.
fn socket_type_name(value: u64) -> Option<&'static str> {
    Some(match value {
        1 => "SOCK_STREAM",
        2 => "SOCK_DGRAM",
        3 => "SOCK_RAW",
        4 => "SOCK_RDM",
        5 => "SOCK_SEQPACKET",
        6 => "SOCK_DCCP",
        10 => "SOCK_PACKET",
        _ => return None,
    })
}

const SOCK_STREAM: u64 = 1;

/// IP protocols, indexed by `sk_protocol`.
fn ip_protocol_name(value: u64) -> Option<&'static str> {
    Some(match value {
        0 => "IPPROTO_IP",
        1 => "IPPROTO_ICMP",
        2 => "IPPROTO_IGMP",
        6 => "IPPROTO_TCP",
        17 => "IPPROTO_UDP",
        58 => "IPPROTO_ICMPV6",
        132 => "IPPROTO_SCTP",
        255 => "IPPROTO_RAW",
        _ => return None,
    })
}

/// TCP connection states, indexed by `skc_state`.
fn tcp_state_name(value: u64) -> Option<&'static str> {
    Some(match value {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        _ => return None,
    })
}

/// BSD socket states, indexed by `socket.state`.
fn socket_state_name(value: u64) -> Option<&'static str> {
    Some(match value {
        0 => "SS_FREE",
        1 => "SS_UNCONNECTED",
        2 => "SS_CONNECTING",
        3 => "SS_CONNECTED",
        4 => "SS_DISCONNECTING",
        _ => return None,
    })
}

/// Everything the network-sockets stage needs out of the symbol table.
pub const SOCKETS_LAYOUT: MemberSet = MemberSet::new(
    STAGE_LINUX_NETWORK_SOCKETS,
    &[
        TypeSpec::new("file", &["file"]).required(
            "this kernel declares no open-file type, so no descriptor could be opened and no \
             socket fd could be reached",
        ),
        TypeSpec::new("socket_alloc", &["socket_alloc"]).required(
            "this kernel declares no socket_alloc type, so a socket inode could not be walked back \
             to its socket",
        ),
        // Not required for construction: reached via follow/embedded, but declared
        // so the layout report names them and the stage fails loudly if absent.
        TypeSpec::new("inet_sock", &["inet_sock"]),
    ],
    &[
        MemberSpec::new("files", &["task_struct"], &["files"]).required(
            "a task structure has no pointer to its open-file table, so no socket could be reached",
        ),
        MemberSpec::new("fdt", &["files_struct"], &["fdt"]).required(
            "the file table has no descriptor table, so the open-file array could not be located",
        ),
        MemberSpec::new("max_fds", &["fdtable"], &["max_fds"]).required(
            "the descriptor table declares no size, so the open-file array could not be bounded",
        ),
        MemberSpec::new("fd", &["fdtable"], &["fd"]).required(
            "the descriptor table has no pointer to the open-file array, so no descriptor could be \
             read",
        ),
        MemberSpec::new("file_dentry", &["file"], &["f_path.dentry"]).required(
            "an open file has no dentry, so its inode could not be reached and socket-ness could \
             not be established",
        ),
        MemberSpec::new("d_inode", &["dentry"], &["d_inode"]).required(
            "a dentry has no inode, so a file could not be tested for being a socket",
        ),
        MemberSpec::new("i_mode", &["inode"], &["i_mode"]).required(
            "an inode has no mode word, so S_ISSOCK could not be evaluated and nothing could be \
             classed as a socket",
        ),
        MemberSpec::new("vfs_inode", &["socket_alloc"], &["vfs_inode"]).required(
            "socket_alloc declares no vfs_inode, so container_of has no offset and a socket inode \
             could not be walked back to its socket",
        ),
        MemberSpec::new("alloc_socket", &["socket_alloc"], &["socket"]).required(
            "socket_alloc declares no embedded socket, so nothing could be read about the endpoint",
        ),
        MemberSpec::new("socket_sk", &["socket"], &["sk"]).required(
            "a socket has no sock pointer, so its family, state, type and addresses could not be \
             read",
        ),
        MemberSpec::new("skc_family", &["sock"], &["__sk_common.skc_family"]).required(
            "a sock has no address family, so nothing could be decoded about the socket at all",
        ),
        MemberSpec::new("skc_state", &["sock"], &["__sk_common.skc_state"]),
        MemberSpec::new("socket_state", &["socket"], &["state"]),
        MemberSpec::new("sk_type", &["sock"], &["sk_type"]),
        MemberSpec::new("sk_protocol", &["sock"], &["sk_protocol"]),
        MemberSpec::new("inet_src_port", &["inet_sock"], &["sport", "inet_sport"]),
        MemberSpec::new(
            "inet_dst_port",
            &["inet_sock"],
            &["dport", "inet_dport", "sk.__sk_common.skc_dport"],
        ),
        MemberSpec::new(
            "inet_src_addr",
            &["inet_sock"],
            &["rcv_saddr", "inet_rcv_saddr", "inet_saddr", "sk.__sk_common.skc_rcv_saddr"],
        ),
        MemberSpec::new(
            "inet_dst_addr",
            &["inet_sock"],
            &["daddr", "inet_daddr", "sk.__sk_common.skc_daddr"],
        ),
        MemberSpec::new("skc_v6_rcv_saddr", &["sock"], &["__sk_common.skc_v6_rcv_saddr"]),
        MemberSpec::new("skc_v6_daddr", &["sock"], &["__sk_common.skc_v6_daddr"]),
    ],
);

/// Caps for one socket survey.
#[derive(Debug, Clone)]
pub struct SocketsConfig {
    /// Most descriptors one task's table will be walked for.
    pub max_fds: u64,
}

impl Default for SocketsConfig {
    fn default() -> Self {
        Self {
            max_fds: MAX_FDS_PER_TASK,
        }
    }
}

/// Why a process contributed the sockets it did — or none.
#[derive(Debug, Clone)]
pub enum SocketOutcome {
    /// The file table was walked for sockets.
    Walked,
    /// No file table (kernel thread / exited task). Not a gap.
    NoFileTable,
    /// The file table exists but would not read. A gap.
    TableUnreadable(String),
    /// `max_fds` past the corruption bound; not walked. A gap.
    CorruptFdTable { max_fds: i64 },
}

impl SocketOutcome {
    fn is_a_gap(&self) -> bool {
        !matches!(self, SocketOutcome::Walked | SocketOutcome::NoFileTable)
    }
    fn class(&self) -> &'static str {
        match self {
            SocketOutcome::Walked => "walked",
            SocketOutcome::NoFileTable => "no_file_table",
            SocketOutcome::TableUnreadable(_) => "table_unreadable",
            SocketOutcome::CorruptFdTable { .. } => "corrupt_fd_table",
        }
    }
    fn detail(&self) -> String {
        match self {
            SocketOutcome::Walked => "the file table was walked for sockets".to_string(),
            SocketOutcome::NoFileTable => {
                "this task has no open-file table, so it held no sockets to read".to_string()
            }
            SocketOutcome::TableUnreadable(detail) => detail.clone(),
            SocketOutcome::CorruptFdTable { max_fds } => format!(
                "the descriptor table claims {max_fds} open descriptors, past the corruption bound \
                 of {MAX_FDS_PER_TASK}; the table was not walked"
            ),
        }
    }
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "class": self.class(), "detail": self.detail(), "is_a_gap": self.is_a_gap() })
    }
}

/// One network socket.
#[derive(Debug, Clone)]
pub struct SocketRow {
    /// The descriptor number the socket is open on.
    pub fd: u64,
    /// Address of the `struct sock`.
    pub sock_address: Field<u64>,
    /// The decoded address family name.
    pub family: Field<String>,
    /// The raw `skc_family` value.
    pub family_raw: Field<u64>,
    /// The decoded socket type.
    pub sock_type: Field<String>,
    /// The raw `sk_type` value.
    pub sock_type_raw: Field<u64>,
    /// The decoded IP protocol (INET only).
    pub protocol: Field<String>,
    /// The raw `sk_protocol` value.
    pub protocol_raw: Field<u64>,
    /// The decoded connection state.
    pub state: Field<String>,
    /// Source address (INET, dotted-quad).
    pub src_addr: Field<String>,
    /// Source port (host order).
    pub src_port: Field<u64>,
    /// Destination address (INET, dotted-quad).
    pub dst_addr: Field<String>,
    /// Destination port (host order).
    pub dst_port: Field<u64>,
    /// Anything odd about the row that did not disqualify it.
    pub notes: Vec<String>,
}

impl SocketRow {
    /// The fields that exist on this build and read `Unavailable`.
    pub fn unreadable_fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for (name, unavailable) in [
            ("family", self.family_raw.is_unavailable()),
            ("state", self.state.is_unavailable()),
            ("src_addr", self.src_addr.is_unavailable()),
            ("dst_addr", self.dst_addr.is_unavailable()),
            ("src_port", self.src_port.is_unavailable()),
            ("dst_port", self.dst_port.is_unavailable()),
        ] {
            if unavailable {
                out.push(name);
            }
        }
        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "fd": self.fd,
            "sock_address": self.sock_address.to_json_address(),
            "family": self.family.to_json(),
            "family_raw": self.family_raw.to_json(),
            "sock_type": self.sock_type.to_json(),
            "sock_type_raw": self.sock_type_raw.to_json(),
            "protocol": self.protocol.to_json(),
            "protocol_raw": self.protocol_raw.to_json(),
            "state": self.state.to_json(),
            "src_addr": self.src_addr.to_json(),
            "src_port": self.src_port.to_json(),
            "dst_addr": self.dst_addr.to_json(),
            "dst_port": self.dst_port.to_json(),
            "unreadable_fields": self.unreadable_fields(),
            "notes": self.notes,
        })
    }
}

/// One process's sockets.
#[derive(Debug, Clone)]
pub struct ProcessSockets {
    pub task_address: u64,
    pub pid: Field<i64>,
    pub ppid: Field<i64>,
    pub comm: Field<String>,
    pub sockets: Vec<SocketRow>,
    pub outcome: SocketOutcome,
    /// A note if the fd loop stopped early.
    pub loop_note: Option<String>,
    /// Descriptors whose socket-ness could not be determined (a gap): the file,
    /// dentry, inode or mode would not read, so the fd might be a socket and was
    /// neither confirmed nor ruled out.
    pub undetermined: Vec<String>,
}

impl ProcessSockets {
    fn is_a_gap(&self) -> bool {
        self.outcome.is_a_gap()
            || self.loop_note.is_some()
            || !self.undetermined.is_empty()
            || self
                .sockets
                .iter()
                .any(|s| !s.unreadable_fields().is_empty())
    }

    fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if self.outcome.is_a_gap() {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the process at the task_struct at {:#x} has no readable file table for \
                     sockets: {}",
                    self.task_address,
                    self.outcome.detail()
                ),
            ));
        }
        if let Some(note) = &self.loop_note {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the fd walk for {:#x} stopped early: {note}",
                    self.task_address
                ),
            ));
        }
        for note in &self.undetermined {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!("{note} (task_struct {:#x})", self.task_address),
            ));
        }
        for socket in &self.sockets {
            let unreadable = socket.unreadable_fields();
            if !unreadable.is_empty() {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "socket on fd {} of {:#x} has field(s) that exist on this build and could \
                         not be read: {}",
                        socket.fd,
                        self.task_address,
                        unreadable.join(", ")
                    ),
                ));
            }
        }
        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "task_address": self.task_address,
            "task_address_hex": format!("{:#x}", self.task_address),
            "pid": signed_to_json(&self.pid),
            "ppid": signed_to_json(&self.ppid),
            "comm": self.comm.to_json(),
            "socket_count": self.sockets.len(),
            "sockets": self.sockets.iter().map(SocketRow::to_json).collect::<Vec<_>>(),
            "outcome": self.outcome.to_json(),
            "loop_note": self.loop_note,
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Every process's sockets, and everything that qualifies the list.
#[derive(Debug, Clone)]
pub struct SocketSurvey {
    pub processes: Vec<ProcessSockets>,
    pub layout: serde_json::Value,
    task_complete: bool,
    task_incomplete: Vec<Incomplete>,
}

impl SocketSurvey {
    pub fn process_count(&self) -> usize {
        self.processes.len()
    }
    pub fn socket_count(&self) -> usize {
        self.processes.iter().map(|p| p.sockets.len()).sum()
    }
    pub fn is_complete(&self) -> bool {
        self.task_complete && !self.processes.iter().any(ProcessSockets::is_a_gap)
    }
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = self.task_incomplete.clone();
        for process in &self.processes {
            out.extend(process.incomplete());
        }
        out
    }
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process_count": self.process_count(),
            "socket_count": self.socket_count(),
            "complete": self.is_complete(),
            "socket_gate": "s_issock_on_inode",
            "family_scope_note": "AF_INET addresses and ports are decoded; non-INET families \
                report family, type and state with not-applicable addresses; IPv6 sock_common \
                addresses are absent before Linux 3.13 and appear as not-declared.",
            "processes": self.processes.iter().map(ProcessSockets::to_json).collect::<Vec<_>>(),
            "layout": self.layout,
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Bind the network-sockets stage's declared layout to this kernel build.
pub fn bind(profile: &LinuxProfile) -> Result<BuildBinding, StageError> {
    let reader = crate::tasks::reader_for(profile);
    Ok(SOCKETS_LAYOUT.bind(&reader)?)
}

/// Walk every process's sockets.
pub fn survey_network_sockets(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    tasks: &TaskList,
    config: &SocketsConfig,
) -> Result<SocketSurvey, StageError> {
    let reader = crate::tasks::reader_for(profile);
    survey_with_reader(&reader, layout, tasks, config)
}

fn survey_with_reader(
    reader: &StructReader,
    layout: &BuildBinding,
    tasks: &TaskList,
    config: &SocketsConfig,
) -> Result<SocketSurvey, StageError> {
    let task_type = layout
        .member("files")?
        .type_name()
        .expect("a required member is declared or binding refused the stage");
    let file_type = layout
        .type_of("file")?
        .type_name()
        .expect("a required type is declared or binding refused the stage");
    let socket_alloc_type = layout
        .type_of("socket_alloc")?
        .type_name()
        .expect("a required type is declared or binding refused the stage");
    let inet_type = layout.type_of("inet_sock").ok().and_then(|t| t.type_name());
    let vfs_inode_offset = layout
        .member("vfs_inode")?
        .offset()
        .expect("a required member has an offset");
    let pointer_size = u64::from(reader.pointer_size()?);

    let ctx = SockCtx {
        reader,
        layout,
        file_type,
        socket_alloc_type,
        inet_type,
        vfs_inode_offset,
    };

    let mut processes = Vec::with_capacity(tasks.tasks.len());
    for task in &tasks.tasks {
        let base = |outcome| ProcessSockets {
            task_address: task.address,
            pid: task.pid.clone(),
            ppid: task.ppid.clone(),
            comm: task.comm.clone(),
            sockets: Vec::new(),
            outcome,
            loop_note: None,
            undetermined: Vec::new(),
        };
        let task_obj = match reader.object(task.address, task_type) {
            Ok(obj) => obj,
            Err(err) => {
                processes.push(base(SocketOutcome::TableUnreadable(format!(
                    "the task_struct could not be reopened: {err}"
                ))));
                continue;
            }
        };
        processes.push(walk_one_task(
            &ctx,
            task,
            &task_obj,
            pointer_size,
            config.max_fds,
        )?);
    }

    Ok(SocketSurvey {
        processes,
        layout: layout.to_json(),
        task_complete: tasks.is_complete(),
        task_incomplete: tasks.incomplete(),
    })
}

/// The resolved reading context shared across one survey.
struct SockCtx<'a> {
    reader: &'a StructReader,
    layout: &'a BuildBinding,
    file_type: &'static str,
    socket_alloc_type: &'static str,
    inet_type: Option<&'static str>,
    vfs_inode_offset: u64,
}

fn walk_one_task(
    ctx: &SockCtx,
    task: &crate::tasks::TaskRecord,
    task_obj: &Obj,
    pointer_size: u64,
    max_fds_cap: u64,
) -> Result<ProcessSockets, StageError> {
    let mut process = ProcessSockets {
        task_address: task.address,
        pid: task.pid.clone(),
        ppid: task.ppid.clone(),
        comm: task.comm.clone(),
        sockets: Vec::new(),
        outcome: SocketOutcome::Walked,
        loop_note: None,
        undetermined: Vec::new(),
    };

    use crate::fdtable::{walk_fd_table, FdSlot, FdTableOutcome};

    // Same fd-table navigation as lsof (CR-005); here we keep only the sockets,
    // and an unreadable slot is a note rather than a row.
    let (outcome, loop_note) = walk_fd_table(
        ctx.reader,
        ctx.layout,
        task_obj,
        pointer_size,
        max_fds_cap,
        |slot| match slot {
            FdSlot::Open { fd, filp } => classify_fd(ctx, fd, filp, &mut process),
            FdSlot::Unreadable { fd, err, .. } => {
                process
                    .undetermined
                    .push(format!("fd {fd}: the fd-array slot would not read ({err})"));
                Ok(())
            }
        },
    )?;

    process.loop_note = loop_note;
    process.outcome = match outcome {
        FdTableOutcome::Walked => SocketOutcome::Walked,
        FdTableOutcome::NoFileTable => SocketOutcome::NoFileTable,
        FdTableOutcome::Unreadable(detail) => SocketOutcome::TableUnreadable(detail),
        FdTableOutcome::Corrupt { max_fds } => SocketOutcome::CorruptFdTable { max_fds },
    };
    Ok(process)
}

/// Decide whether one fd is a socket and, if so, read it into a row.
fn classify_fd(
    ctx: &SockCtx,
    fd: u64,
    filp: u64,
    process: &mut ProcessSockets,
) -> Result<(), StageError> {
    let file_obj = match ctx.reader.object(filp, ctx.file_type) {
        Ok(obj) => obj,
        Err(err) => {
            process
                .undetermined
                .push(format!("fd {fd}: the file struct would not read ({err})"));
            return Ok(());
        }
    };
    let dentry_member = ctx
        .layout
        .member("file_dentry")?
        .member()
        .expect("required");
    let dentry = match file_obj.follow(dentry_member) {
        Ok(Some(dentry)) => dentry,
        Ok(None) => return Ok(()), // no dentry: not a socket we can reach
        Err(err) => {
            process
                .undetermined
                .push(format!("fd {fd}: the file's dentry would not read ({err})"));
            return Ok(());
        }
    };
    let inode_member = ctx.layout.member("d_inode")?.member().expect("required");
    let inode = match dentry.follow(inode_member) {
        Ok(Some(inode)) => inode,
        Ok(None) => return Ok(()), // no inode: not a socket
        Err(err) => {
            process.undetermined.push(format!(
                "fd {fd}: the dentry's inode would not read ({err})"
            ));
            return Ok(());
        }
    };
    let i_mode = ctx.layout.read_unsigned(&inode, "i_mode")?;
    match &i_mode {
        Field::Known(mode) => {
            if mode & S_IFMT != S_IFSOCK {
                return Ok(()); // a real file/pipe/etc — not a socket, not a gap
            }
        }
        Field::Unavailable(_) => {
            process.undetermined.push(format!(
                "fd {fd}: the inode mode would not read, socket-ness undetermined"
            ));
            return Ok(());
        }
        _ => return Ok(()),
    }

    // It is a socket. Recover the socket via container_of(inode, socket_alloc,
    // vfs_inode), bounds-checked.
    let mut row = SocketRow {
        fd,
        sock_address: Field::NotApplicable,
        family: Field::NotApplicable,
        family_raw: Field::NotApplicable,
        sock_type: Field::NotApplicable,
        sock_type_raw: Field::NotApplicable,
        protocol: Field::NotApplicable,
        protocol_raw: Field::NotApplicable,
        state: Field::NotApplicable,
        src_addr: Field::NotApplicable,
        src_port: Field::NotApplicable,
        dst_addr: Field::NotApplicable,
        dst_port: Field::NotApplicable,
        notes: Vec::new(),
    };

    let Some(alloc_addr) = inode.address().checked_sub(ctx.vfs_inode_offset) else {
        row.notes.push(
            "container_of underflowed: the inode sits below the socket_alloc offset, so its socket \
             could not be recovered"
                .to_string(),
        );
        row.family = Field::Unavailable("container_of underflow".into());
        row.family_raw = Field::Unavailable("container_of underflow".into());
        process.sockets.push(row);
        return Ok(());
    };
    let socket_alloc = match ctx.reader.object(alloc_addr, ctx.socket_alloc_type) {
        Ok(obj) => obj,
        Err(err) => {
            row.notes
                .push(format!("the socket_alloc could not be read: {err}"));
            row.family = Field::Unavailable("socket_alloc unreadable".into());
            row.family_raw = Field::Unavailable("socket_alloc unreadable".into());
            process.sockets.push(row);
            return Ok(());
        }
    };
    let socket_member = ctx
        .layout
        .member("alloc_socket")?
        .member()
        .expect("required");
    let socket = match socket_alloc.embedded(socket_member) {
        Ok(socket) => socket,
        Err(err) => {
            row.notes
                .push(format!("the embedded socket could not be read: {err}"));
            process.sockets.push(row);
            return Ok(());
        }
    };

    // socket.sk -> sock.
    let sk_addr = match ctx.layout.read_pointer(&socket, "socket_sk")? {
        Field::Known(0) => {
            row.notes.push(
                "socket.sk is null (socket in teardown); Volatility omits such rows".to_string(),
            );
            process.sockets.push(row);
            return Ok(());
        }
        Field::Known(address) => address,
        other => {
            if other.is_unavailable() {
                row.family = Field::Unavailable("socket.sk would not read".into());
                row.family_raw = Field::Unavailable("socket.sk would not read".into());
            }
            process.sockets.push(row);
            return Ok(());
        }
    };
    row.sock_address = Field::Known(sk_addr);
    let sk_member = ctx.layout.member("socket_sk")?.member().expect("required");
    let sock = match socket.follow(sk_member) {
        Ok(Some(sock)) => sock,
        _ => {
            row.family = Field::Unavailable("the sock struct would not read".into());
            row.family_raw = Field::Unavailable("the sock struct would not read".into());
            process.sockets.push(row);
            return Ok(());
        }
    };

    read_sock_fields(ctx, &socket, &sock, sk_addr, &mut row);
    process.sockets.push(row);
    Ok(())
}

/// Read the family/type/protocol/state and, for INET, the addresses.
fn read_sock_fields(ctx: &SockCtx, socket: &Obj, sock: &Obj, sk_addr: u64, row: &mut SocketRow) {
    let family_raw = ctx
        .layout
        .read_unsigned(sock, "skc_family")
        .unwrap_or(Field::NotApplicable);
    row.family = decode(&family_raw, family_name);
    row.family_raw = family_raw.clone();

    let sk_type = ctx
        .layout
        .read_unsigned(sock, "sk_type")
        .unwrap_or(Field::NotApplicable);
    row.sock_type = decode(&sk_type, socket_type_name);
    row.sock_type_raw = sk_type.clone();

    let sk_protocol = ctx
        .layout
        .read_unsigned(sock, "sk_protocol")
        .unwrap_or(Field::NotApplicable);
    row.protocol_raw = sk_protocol.clone();

    let skc_state = ctx
        .layout
        .read_unsigned(sock, "skc_state")
        .unwrap_or(Field::NotApplicable);
    let socket_state = ctx
        .layout
        .read_unsigned(socket, "socket_state")
        .unwrap_or(Field::NotApplicable);

    let family = family_raw.known().copied();
    let is_stream = sk_type.known().copied() == Some(SOCK_STREAM);

    // State: a stream socket's state is its TCP state; otherwise the BSD socket
    // state. This mirrors Volatility's get_state.
    row.state = if is_stream {
        decode(&skc_state, tcp_state_name)
    } else {
        decode(&socket_state, socket_state_name)
    };

    match family {
        Some(AF_INET) => {
            row.protocol = decode(&sk_protocol, ip_protocol_name);
            if let Some(inet_type) = ctx.inet_type {
                // inet_sock.sk is at offset 0, so the inet_sock sits at the sock
                // address.
                if let Ok(inet) = ctx.reader.object(sk_addr, inet_type) {
                    row.src_port = port(ctx, &inet, "inet_src_port");
                    row.dst_port = port(ctx, &inet, "inet_dst_port");
                    row.src_addr = ipv4(ctx, &inet, "inet_src_addr");
                    row.dst_addr = ipv4(ctx, &inet, "inet_dst_addr");
                } else {
                    row.notes
                        .push("the inet_sock could not be read".to_string());
                }
            } else {
                row.notes.push(
                    "this build declares no inet_sock, so addresses were not read".to_string(),
                );
            }
        }
        Some(AF_INET6) => {
            row.protocol = decode(&sk_protocol, ip_protocol_name);
            // The ports live on inet_sock and are the same members for v6 as for
            // v4, so read them here too rather than leaving an IPv6 socket's
            // ports blank. The v4 dotted-quad addresses do not apply; the v6
            // sock_common addresses are absent before 3.13 (NotDeclared).
            if let Some(inet_type) = ctx.inet_type {
                if let Ok(inet) = ctx.reader.object(sk_addr, inet_type) {
                    row.src_port = port(ctx, &inet, "inet_src_port");
                    row.dst_port = port(ctx, &inet, "inet_dst_port");
                } else {
                    row.notes
                        .push("the inet_sock could not be read for its ports".to_string());
                }
            }
            row.src_addr = v6_note(ctx, sock, "skc_v6_rcv_saddr");
            row.dst_addr = v6_note(ctx, sock, "skc_v6_daddr");
        }
        _ => {
            // Non-INET family: family/type/state reported, addressing N/A.
        }
    }
}

/// Decode a raw field to a named field, preserving the four absence kinds.
fn decode(raw: &Field<u64>, name: fn(u64) -> Option<&'static str>) -> Field<String> {
    match raw {
        Field::Known(value) => match name(*value) {
            Some(text) => Field::Known(text.to_string()),
            None => Field::Known(format!("unknown({value})")),
        },
        Field::NotApplicable => Field::NotApplicable,
        Field::NotDeclared { member } => Field::NotDeclared { member },
        Field::Unavailable(detail) => Field::Unavailable(detail.clone()),
    }
}

/// Read a big-endian port member and return it in host order.
fn port(ctx: &SockCtx, inet: &Obj, key: &'static str) -> Field<u64> {
    match ctx.layout.read_unsigned(inet, key) {
        Ok(Field::Known(value)) => Field::Known(u64::from((value as u16).swap_bytes())),
        Ok(other) => other,
        Err(_) => Field::NotApplicable,
    }
}

/// Read a 4-byte IPv4 address member (stored network order) as dotted-quad.
fn ipv4(ctx: &SockCtx, inet: &Obj, key: &'static str) -> Field<String> {
    let bound = match ctx.layout.member(key) {
        Ok(bound) => bound,
        Err(_) => return Field::NotApplicable,
    };
    let Some(path) = bound.member() else {
        return Field::NotDeclared {
            member: bound.candidates()[0],
        };
    };
    let addr = match inet.member_address(path) {
        Ok(addr) => addr,
        Err(err) => return Field::Unavailable(err.to_string()),
    };
    match ctx.reader.read_bytes(addr, 4) {
        Ok(bytes) if bytes.len() == 4 => Field::Known(format!(
            "{}.{}.{}.{}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )),
        Ok(_) => Field::Unavailable("a short read of the address".into()),
        Err(err) => Field::Unavailable(err.to_string()),
    }
}

/// Surface whether a v6 sock_common address member exists on this build.
fn v6_note(ctx: &SockCtx, sock: &Obj, key: &'static str) -> Field<String> {
    match ctx.layout.member(key) {
        Ok(bound) if bound.is_declared() => {
            // Declared: read 16 bytes and format. (Not present on the 3.2 corpus.)
            match bound
                .member()
                .and_then(|path| sock.member_address(path).ok())
            {
                Some(addr) => match ctx.reader.read_bytes(addr, 16) {
                    Ok(bytes) if bytes.len() == 16 => Field::Known(format_v6(&bytes)),
                    _ => Field::Unavailable("the v6 address would not read".into()),
                },
                None => Field::Unavailable("the v6 address offset could not be resolved".into()),
            }
        }
        Ok(bound) => Field::NotDeclared {
            member: bound.candidates()[0],
        },
        Err(_) => Field::NotApplicable,
    }
}

/// Format 16 bytes as a colon-separated IPv6 address (no `::` compression).
fn format_v6(bytes: &[u8]) -> String {
    (0..8)
        .map(|i| format!("{:x}", u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]])))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_type_protocol_and_state_decode_to_names() {
        assert_eq!(family_name(2), Some("AF_INET"));
        assert_eq!(family_name(1), Some("AF_UNIX"));
        assert_eq!(socket_type_name(1), Some("SOCK_STREAM"));
        assert_eq!(ip_protocol_name(6), Some("IPPROTO_TCP"));
        assert_eq!(tcp_state_name(10), Some("LISTEN"));
        assert_eq!(socket_state_name(3), Some("SS_CONNECTED"));
    }

    #[test]
    fn an_unknown_code_is_reported_not_dropped() {
        let raw = Field::Known(250u64);
        assert_eq!(
            decode(&raw, family_name),
            Field::Known("unknown(250)".into())
        );
    }

    #[test]
    fn absence_kinds_survive_decoding() {
        assert_eq!(
            decode(&Field::<u64>::NotApplicable, family_name),
            Field::NotApplicable
        );
        let nd: Field<u64> = Field::NotDeclared {
            member: "skc_family",
        };
        assert!(decode(&nd, family_name).is_not_declared());
        assert!(decode(&Field::Unavailable("x".into()), family_name).is_unavailable());
    }

    fn socket_row(family_raw: Field<u64>) -> SocketRow {
        SocketRow {
            fd: 7,
            sock_address: Field::Known(0xFFFF_8800_1234_0000),
            family: decode(&family_raw, family_name),
            family_raw,
            sock_type: Field::Known("SOCK_STREAM".into()),
            sock_type_raw: Field::Known(1),
            protocol: Field::Known("IPPROTO_TCP".into()),
            protocol_raw: Field::Known(6),
            state: Field::Known("LISTEN".into()),
            src_addr: Field::Known("0.0.0.0".into()),
            src_port: Field::Known(22),
            dst_addr: Field::Known("0.0.0.0".into()),
            dst_port: Field::Known(0),
            notes: Vec::new(),
        }
    }

    #[test]
    fn a_read_socket_row_declares_nothing_unreadable() {
        assert!(socket_row(Field::Known(2)).unreadable_fields().is_empty());
    }

    #[test]
    fn an_unreadable_family_is_a_named_gap() {
        let row = socket_row(Field::Unavailable("the sock page was not acquired".into()));
        assert_eq!(row.unreadable_fields(), vec!["family"]);
    }

    #[test]
    fn a_kernel_thread_with_no_file_table_is_not_a_gap() {
        let p = ProcessSockets {
            task_address: 0x1000,
            pid: Field::Known(2),
            ppid: Field::Known(0),
            comm: Field::Known("kthreadd".into()),
            sockets: Vec::new(),
            outcome: SocketOutcome::NoFileTable,
            loop_note: None,
            undetermined: Vec::new(),
        };
        assert!(!p.is_a_gap());
    }

    #[test]
    fn an_undetermined_fd_is_a_gap() {
        let p = ProcessSockets {
            task_address: 0x1000,
            pid: Field::Known(1),
            ppid: Field::Known(0),
            comm: Field::Known("init".into()),
            sockets: Vec::new(),
            outcome: SocketOutcome::Walked,
            loop_note: None,
            undetermined: vec!["fd 5: undetermined".into()],
        };
        assert!(
            p.is_a_gap(),
            "an fd that might be a socket and could not be read is a gap"
        );
    }
}

#[cfg(test)]
mod walk_tests {
    use std::sync::Arc;

    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_memory::object::ListStop;
    use seance_memory::{MemoryLayer, PhysicalLayer};
    use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

    use super::*;
    use crate::tasks::{TaskList, TaskRecord};

    const TASK: u64 = 0x1000;
    const FILES: u64 = 0x2000;
    const FDT: u64 = 0x2400;
    const FD_ARRAY: u64 = 0x2500;
    const FILE_SOCK: u64 = 0x3000; // fd 0: a socket
    const FILE_REG: u64 = 0x3200; // fd 1: a regular file
    const DENTRY_SOCK: u64 = 0x3400;
    const INODE_SOCK: u64 = 0x3600; // socket inode
    const SOCKET_ALLOC: u64 = INODE_SOCK - 48; // container_of
    const SOCK: u64 = 0x3A00;
    const DENTRY_REG: u64 = 0x3C00;
    const INODE_REG: u64 = 0x3E00; // regular-file inode

    // socket_alloc: socket@0, vfs_inode@48. socket: state@0, type@4, sk@32.
    // So SOCKET_ALLOC+32 holds sk; SOCK must be reachable.
    const FIXTURE_ISF: &str = r#"{
      "metadata": {"format":"6.2.0","producer":{"name":"seance-sockstat-fixture","version":"1.0.0"},"linux":{"symbols":[],"types":[]}},
      "base_types": {
        "pointer": {"size":8,"signed":false,"kind":"int","endian":"little"},
        "unsigned int": {"size":4,"signed":false,"kind":"int","endian":"little"},
        "short unsigned int": {"size":2,"signed":false,"kind":"int","endian":"little"},
        "unsigned char": {"size":1,"signed":false,"kind":"int","endian":"little"},
        "int": {"size":4,"signed":true,"kind":"int","endian":"little"},
        "void": {"size":0,"signed":false,"kind":"void","endian":"little"}
      },
      "user_types": {
        "sock_common": {"size":80,"kind":"struct","fields":{
          "skc_daddr":{"offset":0,"type":{"kind":"base","name":"unsigned int"}},
          "skc_rcv_saddr":{"offset":4,"type":{"kind":"base","name":"unsigned int"}},
          "skc_family":{"offset":12,"type":{"kind":"base","name":"short unsigned int"}},
          "skc_state":{"offset":14,"type":{"kind":"base","name":"unsigned char"}}
        }},
        "sock": {"size":624,"kind":"struct","fields":{
          "__sk_common":{"offset":0,"type":{"kind":"struct","name":"sock_common"}},
          "sk_protocol":{"offset":289,"type":{"kind":"base","name":"unsigned char"}},
          "sk_type":{"offset":290,"type":{"kind":"base","name":"short unsigned int"}}
        }},
        "inet_sock": {"size":800,"kind":"struct","fields":{
          "sk":{"offset":0,"type":{"kind":"struct","name":"sock"}},
          "inet_dport":{"offset":632,"type":{"kind":"base","name":"short unsigned int"}},
          "inet_sport":{"offset":644,"type":{"kind":"base","name":"short unsigned int"}}
        }},
        "socket": {"size":48,"kind":"struct","fields":{
          "state":{"offset":0,"type":{"kind":"base","name":"unsigned int"}},
          "type":{"offset":4,"type":{"kind":"base","name":"short unsigned int"}},
          "sk":{"offset":32,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"sock"}}}
        }},
        "inode": {"size":552,"kind":"struct","fields":{
          "i_mode":{"offset":0,"type":{"kind":"base","name":"short unsigned int"}}
        }},
        "socket_alloc": {"size":600,"kind":"struct","fields":{
          "socket":{"offset":0,"type":{"kind":"struct","name":"socket"}},
          "vfs_inode":{"offset":48,"type":{"kind":"struct","name":"inode"}}
        }},
        "dentry": {"size":192,"kind":"struct","fields":{
          "d_inode":{"offset":48,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"inode"}}}
        }},
        "file": {"size":208,"kind":"struct","fields":{
          "f_path":{"offset":16,"type":{"kind":"struct","name":"path"}}
        }},
        "path": {"size":16,"kind":"struct","fields":{
          "dentry":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"dentry"}}}
        }},
        "fdtable": {"size":56,"kind":"struct","fields":{
          "max_fds":{"offset":0,"type":{"kind":"base","name":"unsigned int"}},
          "fd":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"pointer","subtype":{"kind":"struct","name":"file"}}}}
        }},
        "files_struct": {"size":704,"kind":"struct","fields":{
          "fdt":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"fdtable"}}}
        }},
        "task_struct": {"size":1784,"kind":"struct","fields":{
          "files":{"offset":1152,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"files_struct"}}}
        }}
      },
      "enums": {},
      "symbols": {}
    }"#;

    struct Image {
        bytes: Vec<u8>,
    }
    impl Image {
        fn new() -> Self {
            Self {
                bytes: vec![0u8; 0x8000],
            }
        }
        fn put(&mut self, a: u64, d: &[u8]) {
            let at = a as usize;
            self.bytes[at..at + d.len()].copy_from_slice(d);
        }
        fn u64(&mut self, a: u64, v: u64) {
            self.put(a, &v.to_le_bytes());
        }
        fn u32(&mut self, a: u64, v: u32) {
            self.put(a, &v.to_le_bytes());
        }
        fn u16(&mut self, a: u64, v: u16) {
            self.put(a, &v.to_le_bytes());
        }
    }

    fn reader() -> StructReader {
        let mut m = Image::new();
        m.u64(TASK + 1152, FILES);
        m.u64(FILES + 8, FDT);
        m.u32(FDT, 2);
        m.u64(FDT + 8, FD_ARRAY);
        m.u64(FD_ARRAY, FILE_SOCK); // fd 0 -> socket file
        m.u64(FD_ARRAY + 8, FILE_REG); // fd 1 -> regular file

        // fd 0: socket file -> dentry -> inode (S_IFSOCK).
        m.u64(FILE_SOCK + 24, DENTRY_SOCK); // f_path.dentry (file+16+8)
        m.u64(DENTRY_SOCK + 48, INODE_SOCK); // dentry.d_inode
        m.u16(INODE_SOCK, 0xC000); // i_mode = S_IFSOCK

        // socket_alloc = INODE_SOCK - 48; socket embedded at +0; socket.sk@32.
        m.u16(SOCKET_ALLOC + 4, 1); // socket.type (unused by decode; sk_type drives)
        m.u64(SOCKET_ALLOC + 32, SOCK); // socket.sk -> sock
                                        // sock: skc_family@12=AF_INET, skc_state@14=LISTEN(10), sk_protocol@289=TCP(6), sk_type@290=STREAM(1).
        m.u16(SOCK + 12, 2);
        m.put(SOCK + 14, &[10]);
        m.put(SOCK + 289, &[6]);
        m.u16(SOCK + 290, 1);
        // inet_sock sits at SOCK (inet_sock.sk@0). ports big-endian: 22 -> bytes 00 16.
        m.put(SOCK + 644, &[0x00, 0x16]); // inet_sport = 22
        m.put(SOCK + 632, &[0x00, 0x00]); // inet_dport = 0
                                          // addresses via sk.__sk_common: skc_rcv_saddr@4, skc_daddr@0 (network order).
        m.put(SOCK + 4, &[0, 0, 0, 0]); // src 0.0.0.0
        m.put(SOCK, &[0, 0, 0, 0]); // dst 0.0.0.0

        // fd 1: regular file -> dentry -> inode (S_IFREG).
        m.u64(FILE_REG + 24, DENTRY_REG);
        m.u64(DENTRY_REG + 48, INODE_REG);
        m.u16(INODE_REG, 0x8000); // S_IFREG

        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(m.bytes));
        let layer: Arc<dyn MemoryLayer> =
            Arc::new(PhysicalLayer::raw(source).expect("a non-empty image"));
        let symbols = Arc::new(
            SymbolTable::compile_source(
                seance_symbols::load_slice(FIXTURE_ISF.as_bytes(), &DecompressLimits::default())
                    .expect("loads"),
                &CompileOptions::default(),
            )
            .expect("compiles"),
        );
        StructReader::new(layer, symbols)
    }

    fn one_task_list() -> TaskList {
        let mut task = TaskRecord::address_only_for_test(TASK);
        task.pid = Field::Known(1);
        task.ppid = Field::Known(0);
        task.comm = Field::Known("init".into());
        TaskList {
            init_task: 0,
            head: 0,
            links_offset: 0,
            tasks: vec![task],
            stop: ListStop::Wrapped,
            layout: serde_json::json!({}),
        }
    }

    #[test]
    fn the_walk_finds_the_socket_decodes_it_and_ignores_the_regular_file() {
        let reader = reader();
        let layout = SOCKETS_LAYOUT.bind(&reader).expect("the fixture binds");
        let tasks = one_task_list();

        let survey = super::survey_with_reader(&reader, &layout, &tasks, &SocketsConfig::default())
            .expect("the survey runs");

        assert_eq!(survey.process_count(), 1);
        // The regular file at fd 1 must not appear as a socket.
        assert_eq!(
            survey.socket_count(),
            1,
            "one socket, the regular file excluded"
        );

        let process = &survey.processes[0];
        assert!(matches!(process.outcome, SocketOutcome::Walked));
        assert!(process.undetermined.is_empty());
        let socket = &process.sockets[0];
        assert_eq!(socket.fd, 0);
        assert_eq!(socket.family.known().map(String::as_str), Some("AF_INET"));
        assert_eq!(
            socket.sock_type.known().map(String::as_str),
            Some("SOCK_STREAM")
        );
        assert_eq!(
            socket.protocol.known().map(String::as_str),
            Some("IPPROTO_TCP")
        );
        assert_eq!(socket.state.known().map(String::as_str), Some("LISTEN"));
        assert_eq!(socket.src_addr.known().map(String::as_str), Some("0.0.0.0"));
        assert_eq!(
            socket.src_port.known(),
            Some(&22),
            "the big-endian port is converted to host order"
        );
        assert!(!process.is_a_gap());
    }
}
