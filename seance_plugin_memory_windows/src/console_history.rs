//! Console command history from a console host's heap (`ROADMAP` §5.3,
//! the question upstream's `cmdscan` answers).
//!
//! # What an examiner learns
//!
//! What was typed at a console — the lines a person entered at `cmd.exe`, in
//! the order the console host kept them — including by a client process that
//! has since exited, for as long as the console host that held the history is
//! still in memory. It is one of the few places a typed command survives that
//! neither the registry nor the file system records.
//!
//! # Where the layout comes from, and what that means for reach
//!
//! **In-house, from a known plaintext, on one build.** The history is a
//! `std::vector<std::wstring>` inside the console host's own private heap. No
//! public symbol file describes it (the host's types are absent from the
//! kernel's ISF, and Microsoft publishes no PDB with them), and this stage
//! does not use a third party's per-build tables: the layout below was read
//! off the bytes of a capture in which the commands typed were known
//! (`~/win11-lab/console/GROUND-TRUTH.txt`), and nothing was taken from any
//! plugin's source. The container is the MSVC standard library's, which is
//! stable across the toolchain generations Windows 10 and 11 ship:
//!
//! ```text
//!   +0x00  begin   u64  first element of the vector
//!   +0x08  end     u64  one past the last element
//!   +0x10  cap     u64  end of the allocation
//!   +0x18  limit   u32  the history's command limit (50 on the capture)
//!   +0x20  name    wstring  the client's application name ("cmd.exe")
//!
//!   wstring (32 bytes): 16 bytes that are either the characters (capacity 7)
//!                       or a pointer to them, then size u64, then capacity u64
//! ```
//!
//! Only the object above is recognised, and it was observed on **one** build
//! of the host (Windows 11 26200.6584). A host built differently is not
//! decoded wrongly — the structural checks fail and it yields nothing — but
//! *nothing found is not* "nothing typed" there, and the record says so for
//! every host it examined. A second build is what would move that.
//!
//! # How a history is recognised, and how it is not confused
//!
//! The heap is swept on 8-byte boundaries for a vector triple that satisfies
//! every check at once: three user-space pointers, `begin < end <= cap`, both
//! spans a whole number of 32-byte strings, a plausible command limit, and an
//! application name that decodes to printable text. Then every element is
//! decoded and must satisfy the string's own invariants (`size <= capacity`,
//! the characters readable). An element that does not is **reported as
//! unreadable, not dropped**, and marks the record incomplete.
//!
//! # What is deliberately not claimed
//!
//! * The vector is presented **in the order stored**. That order was oldest
//!   first on the capture; it is not asserted for a history that has wrapped.
//! * A line still being edited, or read but not yet entered, is not in the
//!   vector and is not reported.
//! * Nothing is read from the screen buffer. What a command *printed* is a
//!   separate structure (the `consoles` question) and is not answered here.
//! * A history whose vector is empty is unreachable by this sweep: an empty
//!   vector has null pointers and matches no check. It says nothing typed at
//!   that console *and is not evidence of it*.
//! * A stale copy in freed heap is reported like a live one if its bytes still
//!   satisfy every check, and the address is on the record so the two can be
//!   told apart. Nothing here decides which is which.
//! * Hosts are found **by image name** (`conhost.exe`, `OpenConsole.exe`).
//!   A console host running under another name is not examined, and the
//!   record lists the console *clients* it saw, so that clients without a host
//!   are visible rather than silent.

use std::collections::BTreeSet;
use std::ops::Range;
use std::sync::Arc;

use seance_core::data_source::DataSource;
use seance_core::io::IncompleteReason;
use seance_memory::translate::{TableCache, TranslateError, VirtualLayer};
use seance_memory::Incomplete;
use serde_json::{json, Value};

use crate::process::{ProcessList, ProcessRecord, ProcessSymbols};
use crate::profile::WindowsProfile;
use crate::vad::{VadSymbols, VadWalkConfig};

/// Image names that host a console, compared case-insensitively.
pub const HOST_NAMES: &[&str] = &["conhost.exe", "openconsole.exe"];

/// Image names of processes that are usually console clients. Listed on the
/// record so that a client with no host reads as a gap, not as silence.
pub const CLIENT_NAMES: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wsl.exe",
    "python.exe",
    "ssh.exe",
];

/// Bytes in one `std::wstring` on x64.
const WSTRING: u64 = 32;
/// The highest user-mode address on 64-bit Windows.
const USER_LIMIT: u64 = 0x0000_8000_0000_0000;

/// Caps. Reaching any is stated.
#[derive(Debug, Clone)]
pub struct ConsoleHistoryConfig {
    /// Histories published per host.
    pub max_histories: usize,
    /// Commands decoded per history.
    pub max_commands: u64,
    /// Characters kept of one command.
    pub max_command_chars: u64,
    /// The largest allocation swept as a whole; a larger one is swept in
    /// full too but its size is stated.
    pub max_region_bytes: u64,
    /// The highest command limit accepted as plausible.
    pub max_limit: u32,
}

impl Default for ConsoleHistoryConfig {
    fn default() -> Self {
        Self {
            max_histories: 64,
            max_commands: 4096,
            max_command_chars: 0x8000,
            max_region_bytes: 1 << 30,
            max_limit: 0xFFFF,
        }
    }
}

/// One stored command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryCommand {
    /// Position in the vector, from 0.
    pub index: u64,
    /// The text, when it read.
    pub text: Option<String>,
    /// Why it did not, when it did not.
    pub unreadable: Option<String>,
    /// The string's stated length in characters.
    pub length_chars: u64,
}

/// One recognised history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleHistory {
    /// Where the vector triple was found, in the host's own address space.
    pub address: u64,
    /// The application name the history is kept for.
    pub application: String,
    /// The command limit the history states.
    pub limit: u32,
    /// Elements the vector holds.
    pub commands: Vec<HistoryCommand>,
    /// Elements the vector has room for.
    pub capacity_commands: u64,
    /// Commands not decoded because a cap fired.
    pub commands_not_decoded: u64,
}

impl ConsoleHistory {
    /// Whether every stored command was read.
    pub fn is_complete(&self) -> bool {
        self.commands_not_decoded == 0 && self.commands.iter().all(|c| c.text.is_some())
    }

    pub fn to_json(&self) -> Value {
        json!({
            "address": format!("{:#018x}", self.address),
            "application": self.application,
            "command_limit": self.limit,
            "commands_stored": self.commands.len() as u64 + self.commands_not_decoded,
            "capacity_commands": self.capacity_commands,
            "commands_not_decoded": self.commands_not_decoded,
            "commands": self.commands.iter().map(|c| json!({
                "index": c.index,
                "text": c.text,
                "length_chars": c.length_chars,
                "unreadable": c.unreadable,
            })).collect::<Vec<_>>(),
        })
    }
}

/// What sweeping one host's space found.
#[derive(Debug, Clone, Default)]
pub struct HostSweep {
    pub histories: Vec<ConsoleHistory>,
    pub histories_truncated: bool,
    pub bytes_swept: u64,
    /// Bytes whose page table entry says the page is not resident: never
    /// touched, decommitted, or trimmed. Not distinguished, and **not** counted
    /// as a gap in the examination: most of a heap's reserved range is this.
    pub bytes_not_resident: u64,
    /// Bytes on a pagefile that is not part of this evidence. Evidence exists
    /// and was not read: a gap.
    pub bytes_paged_out: u64,
    /// Bytes that would not read for any other reason. A gap.
    pub bytes_unreadable: u64,
    pub ranges_swept: usize,
}

/// One console host examined.
#[derive(Debug, Clone)]
pub struct HostRecord {
    pub name: String,
    pub pid: Option<u64>,
    pub ppid: Option<u64>,
    pub process_address: u64,
    pub sweep: Option<HostSweep>,
    /// Why the host was not swept.
    pub not_swept_because: Option<String>,
}

impl HostRecord {
    pub fn is_complete(&self) -> bool {
        match &self.sweep {
            Some(s) => {
                s.bytes_unreadable == 0
                    && s.bytes_paged_out == 0
                    && !s.histories_truncated
                    && s.histories.iter().all(ConsoleHistory::is_complete)
            }
            None => false,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "host": self.name,
            "pid": self.pid,
            "ppid": self.ppid,
            "process_address": format!("{:#018x}", self.process_address),
            "swept": self.sweep.is_some(),
            "not_swept_because": self.not_swept_because,
            "histories": self.sweep.as_ref().map(|s| s.histories.iter().map(ConsoleHistory::to_json).collect::<Vec<_>>()),
            "histories_found": self.sweep.as_ref().map(|s| s.histories.len()),
            "histories_truncated": self.sweep.as_ref().map(|s| s.histories_truncated),
            "bytes_swept": self.sweep.as_ref().map(|s| s.bytes_swept),
            "bytes_not_resident": self.sweep.as_ref().map(|s| s.bytes_not_resident),
            "bytes_paged_out": self.sweep.as_ref().map(|s| s.bytes_paged_out),
            "bytes_unreadable": self.sweep.as_ref().map(|s| s.bytes_unreadable),
            "ranges_swept": self.sweep.as_ref().map(|s| s.ranges_swept),
        })
    }
}

/// A console client seen on the process list.
#[derive(Debug, Clone)]
pub struct ClientRecord {
    pub name: String,
    pub pid: Option<u64>,
    pub ppid: Option<u64>,
}

/// The survey.
#[derive(Debug, Clone)]
pub struct ConsoleHistorySurvey {
    pub hosts: Vec<HostRecord>,
    pub clients: Vec<ClientRecord>,
    pub process_list_complete: bool,
}

impl ConsoleHistorySurvey {
    pub fn histories_total(&self) -> usize {
        self.hosts
            .iter()
            .filter_map(|h| h.sweep.as_ref())
            .map(|s| s.histories.len())
            .sum()
    }

    pub fn is_complete(&self) -> bool {
        self.process_list_complete && self.hosts.iter().all(HostRecord::is_complete)
    }

    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if !self.process_list_complete {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                "the process list did not walk end to end, so a console host may be missing from it",
            ));
        }
        for host in &self.hosts {
            if let Some(why) = &host.not_swept_because {
                out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!("{} pid {:?} was not swept: {why}", host.name, host.pid),
                ));
            }
            if let Some(s) = &host.sweep {
                if s.bytes_unreadable + s.bytes_paged_out > 0 {
                    out.push(Incomplete::new(
                        IncompleteReason::ShortRead,
                        format!(
                            "{} pid {:?}: {} byte(s) of its heap are on a pagefile this evidence \
                             does not hold and {} would not read, so a history there was not seen",
                            host.name, host.pid, s.bytes_paged_out, s.bytes_unreadable
                        ),
                    ));
                }
            }
        }
        out
    }

    pub fn describe(&self) -> String {
        let found = self.histories_total();
        if self.hosts.is_empty() {
            return format!(
                "No console host ({}) is on the process list, so there was no console heap to \
                 read. {} console client process(es) are listed{}. This is not evidence that \
                 nothing was typed: a console host under another name, or one this list does \
                 not hold, is not examined.",
                HOST_NAMES.join(", "),
                self.clients.len(),
                if self.process_list_complete {
                    ""
                } else {
                    " and the list did not walk end to end"
                }
            );
        }
        format!(
            "{} console host(s) swept, {found} command history/histories recognised. The layout \
             was derived on one build of the host and a host built differently yields nothing \
             rather than something wrong; finding none is not evidence that nothing was typed.",
            self.hosts.len()
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "summary": self.describe(),
            "hosts": self.hosts.iter().map(HostRecord::to_json).collect::<Vec<_>>(),
            "hosts_total": self.hosts.len(),
            "histories_total": self.histories_total(),
            "console_clients_listed": self.clients.iter().map(|c| json!({
                "name": c.name, "pid": c.pid, "ppid": c.ppid,
            })).collect::<Vec<_>>(),
            "host_names_looked_for": HOST_NAMES,
            "process_list_complete": self.process_list_complete,
            "layout_basis":
                "The history layout (a vector of MSVC wide strings, a command limit, an \
                 application name) was derived in-house from a capture whose typed commands were \
                 known, on Windows 11 build 26200.6584 only. Another build of the console host is \
                 not decoded wrongly: the structural checks fail and it yields nothing, which is \
                 not evidence that nothing was typed.",
            "order_basis":
                "Commands are given in the order stored, oldest first on the capture; that order \
                 is not asserted for a history that has wrapped. A line being edited and not yet \
                 entered is not in the vector. The screen buffer (what a command printed) is not \
                 read.",
        })
    }
}

// ── Reading ─────────────────────────────────────────────────────────────────

fn read_exact(space: &dyn DataSource, address: u64, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut done = 0usize;
    while done < len {
        // A page at a time, so a read that crosses into a hole fails whole
        // rather than returning short bytes that would decode as text.
        let step = (len - done).min(4096 - ((address + done as u64) % 4096) as usize);
        match space.read_at(address + done as u64, &mut buf[done..done + step]) {
            Ok(n) if n == step => done += step,
            _ => return None,
        }
    }
    Some(buf)
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn decode_utf16(bytes: &[u8]) -> Option<String> {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16(&units).ok()
}

fn is_printable(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| !c.is_control() && c != '\u{fffd}')
}

/// Why a 32-byte object did not decode as a string.
enum StringFault {
    /// The bytes cannot be a `std::wstring` at all: the object is not one.
    NotAString(String),
    /// They can, and its characters would not read: paged out, or the string
    /// is real and the evidence is missing.
    Unreadable(String),
}

impl StringFault {
    fn why(self) -> String {
        match self {
            Self::NotAString(w) | Self::Unreadable(w) => w,
        }
    }
}

/// One `std::wstring`, decoded from its 32 bytes.
fn read_wstring(
    space: &dyn DataSource,
    raw: &[u8],
    max_chars: u64,
) -> Result<(String, u64), StringFault> {
    use StringFault::{NotAString, Unreadable};
    let size = u64_at(raw, 16);
    let cap = u64_at(raw, 24);
    if size > cap {
        return Err(NotAString(format!("size {size} exceeds capacity {cap}")));
    }
    if cap > 0x10_0000 {
        return Err(NotAString(format!("capacity {cap:#x} is implausible")));
    }
    let take = size.min(max_chars);
    let bytes = if cap < 8 {
        // Small-string form: the characters are in the first 16 bytes.
        raw[..(take as usize) * 2].to_vec()
    } else {
        let ptr = u64_at(raw, 0);
        if ptr == 0 || ptr >= USER_LIMIT {
            return Err(NotAString(format!(
                "its character pointer {ptr:#x} is not a user address"
            )));
        }
        if take == 0 {
            Vec::new()
        } else {
            read_exact(space, ptr, take as usize * 2).ok_or_else(|| {
                Unreadable(format!("its characters at {ptr:#018x} would not read"))
            })?
        }
    };
    let text = decode_utf16(&bytes)
        .ok_or_else(|| NotAString("its characters are not valid UTF-16".to_string()))?;
    Ok((text, size))
}

/// Try one candidate offset. `head` holds the 64 bytes at the candidate.
fn try_history(
    space: &dyn DataSource,
    address: u64,
    head: &[u8],
    cfg: &ConsoleHistoryConfig,
) -> Option<ConsoleHistory> {
    let begin = u64_at(head, 0);
    let end = u64_at(head, 8);
    let cap = u64_at(head, 16);
    if begin == 0
        || !begin.is_multiple_of(8)
        || begin >= USER_LIMIT
        || end >= USER_LIMIT
        || cap >= USER_LIMIT
    {
        return None;
    }
    if !(begin < end && end <= cap) {
        return None;
    }
    let span = end - begin;
    let room = cap - begin;
    if !span.is_multiple_of(WSTRING)
        || !room.is_multiple_of(WSTRING)
        || span / WSTRING > 65_536
        || room / WSTRING > 65_536
    {
        return None;
    }
    let limit = u32_at(head, 0x18);
    if limit == 0 || limit > cfg.max_limit {
        return None;
    }
    let (application, _) = read_wstring(space, &head[0x20..0x40], 260).ok()?;
    // A real history's elements are all strings. One that is structurally not
    // a string means this triple is some other vector, and it is refused
    // whole; one whose characters merely will not read is kept and reported.
    if !is_printable(&application) {
        return None;
    }

    let stored = span / WSTRING;
    let decode = stored.min(cfg.max_commands);
    let mut commands = Vec::new();
    for i in 0..decode {
        let at = begin + i * WSTRING;
        let cmd = match read_exact(space, at, WSTRING as usize) {
            None => HistoryCommand {
                index: i,
                text: None,
                unreadable: Some(format!("the element at {at:#018x} would not read")),
                length_chars: 0,
            },
            Some(raw) => match read_wstring(space, &raw, cfg.max_command_chars) {
                Ok((text, size)) => HistoryCommand {
                    index: i,
                    text: Some(text),
                    unreadable: None,
                    length_chars: size,
                },
                Err(StringFault::NotAString(_)) => return None,
                Err(fault @ StringFault::Unreadable(_)) => HistoryCommand {
                    index: i,
                    text: None,
                    unreadable: Some(fault.why()),
                    length_chars: u64_at(&raw, 16),
                },
            },
        };
        commands.push(cmd);
    }
    // A vector whose first element is not a string at all is not a history.
    if commands.first().is_some_and(|c| c.text.is_none())
        && commands.iter().all(|c| c.text.is_none())
    {
        return None;
    }
    Some(ConsoleHistory {
        address,
        application,
        limit,
        commands,
        capacity_commands: room / WSTRING,
        commands_not_decoded: stored - decode,
    })
}

/// Sweep ranges of one host's address space for histories.
pub fn sweep_ranges(
    space: &dyn DataSource,
    ranges: &[Range<u64>],
    cfg: &ConsoleHistoryConfig,
    classify: Option<&VirtualLayer>,
) -> HostSweep {
    const CHUNK: usize = 64 * 1024;
    const NEED: usize = 0x40;
    let mut out = HostSweep::default();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for range in ranges {
        if range.end <= range.start {
            continue;
        }
        out.ranges_swept += 1;
        let mut base = range.start & !7;
        let mut carry: Vec<u8> = Vec::new();
        let mut carry_base = base;
        while base < range.end {
            let len = ((range.end - base) as usize).min(CHUNK);
            // Read a page at a time; an unreadable page is counted and zeroed
            // so the bytes on either side keep their alignment.
            let mut buf = vec![0u8; len];
            let mut off = 0usize;
            while off < len {
                let step = (len - off).min(4096 - ((base + off as u64) % 4096) as usize);
                match space.read_at(base + off as u64, &mut buf[off..off + step]) {
                    Ok(n) if n == step => {}
                    _ => {
                        let va = base + off as u64;
                        let kind = classify.map(|l| l.translate(va));
                        match kind {
                            Some(Err(TranslateError::NotPresent { .. })) => {
                                out.bytes_not_resident += step as u64
                            }
                            Some(Err(TranslateError::SwappedOut { .. })) => {
                                out.bytes_paged_out += step as u64
                            }
                            _ => out.bytes_unreadable += step as u64,
                        }
                        buf[off..off + step].fill(0);
                    }
                }
                off += step;
            }
            out.bytes_swept += len as u64;
            // Continue from the previous chunk's tail so a triple straddling
            // the boundary is seen once, from the chunk that holds its start.
            let mut window = std::mem::take(&mut carry);
            let window_base = if window.is_empty() { base } else { carry_base };
            window.extend_from_slice(&buf);
            let mut o = 0usize;
            let limit = window.len().saturating_sub(NEED);
            while o <= limit && window.len() >= NEED {
                let w = &window[o..o + 24];
                // Cheap pre-filter before any read: begin < end <= cap.
                let b = u64_at(w, 0);
                if b != 0 && b < USER_LIMIT {
                    let e = u64_at(w, 8);
                    let c = u64_at(w, 16);
                    if b < e && e <= c && c < USER_LIMIT {
                        let at = window_base + o as u64;
                        if !seen.contains(&at) {
                            if let Some(h) = try_history(space, at, &window[o..o + NEED], cfg) {
                                seen.insert(at);
                                if out.histories.len() >= cfg.max_histories {
                                    out.histories_truncated = true;
                                } else {
                                    out.histories.push(h);
                                }
                            }
                        }
                    }
                }
                o += 8;
            }
            // Keep what has not been examined.
            let keep_from = o.min(window.len());
            carry = window[keep_from..].to_vec();
            carry_base = window_base + keep_from as u64;
            base += len as u64;
        }
    }
    out
}

fn name_of(p: &ProcessRecord) -> Option<String> {
    p.image_file_name.known().cloned()
}

/// Survey every console host on the process list.
pub fn survey_console_history(
    profile: &WindowsProfile,
    process_symbols: &ProcessSymbols,
    vad_symbols: &VadSymbols,
    list: &ProcessList,
    cfg: &ConsoleHistoryConfig,
) -> ConsoleHistorySurvey {
    let cache = Arc::new(TableCache::new());
    let vad_config = VadWalkConfig::for_profile(profile);
    let mut hosts = Vec::new();
    let mut clients = Vec::new();
    for p in &list.processes {
        let Some(name) = name_of(p) else { continue };
        let lower = name.to_ascii_lowercase();
        let pid = p.pid.known().copied();
        let ppid = p.ppid.known().copied();
        if CLIENT_NAMES.contains(&lower.as_str()) {
            clients.push(ClientRecord {
                name: name.clone(),
                pid,
                ppid,
            });
        }
        if !HOST_NAMES.contains(&lower.as_str()) {
            continue;
        }
        let mut host = HostRecord {
            name,
            pid,
            ppid,
            process_address: p.address,
            sweep: None,
            not_swept_because: None,
        };
        let tree = crate::vad::list_vads(profile, vad_symbols, p.address, &vad_config);
        let space =
            crate::process::process_virtual_space(profile, process_symbols, p.address, &cache);
        match (tree, space) {
            (Ok(tree), Ok(space)) => {
                let ranges: Vec<Range<u64>> = tree
                    .vads
                    .iter()
                    // A mapped file is an image or a data file, never the heap
                    // this structure lives in.
                    .filter(|v| v.file.is_definitely_unbacked())
                    .filter(|v| v.size() <= cfg.max_region_bytes)
                    .filter_map(|v| v.end.checked_add(1).map(|e| v.start..e))
                    .collect();
                host.sweep = Some(sweep_ranges(
                    space.as_ref(),
                    &ranges,
                    cfg,
                    Some(space.as_ref()),
                ));
            }
            (Err(e), _) => {
                host.not_swept_because = Some(format!("its allocation tree would not walk: {e}"))
            }
            (_, Err(e)) => {
                host.not_swept_because = Some(format!("it has no readable address space: {e}"))
            }
        }
        hosts.push(host);
    }
    ConsoleHistorySurvey {
        hosts,
        clients,
        process_list_complete: list.is_complete(),
    }
}
