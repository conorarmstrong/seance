//! TCP stream reassembly: the bytes a conversation carried, in order, with
//! every gap stated (`ROADMAP` §4.3 stage 2).
//!
//! # What this is for
//!
//! Stage 1 of the network tier reaches the *address* a machine was talking to.
//! This is what it was **saying**: the request that was sent, the page that
//! came back, the certificate the server presented. None of that is in any one
//! packet — TCP is a byte stream cut into segments that arrive out of order,
//! get retransmitted, and overlap — so an examiner who wants the exchange needs
//! the stream put back together.
//!
//! # A gap is never closed
//!
//! **The reassembled stream is a list of runs, not one buffer.** A capture with
//! a snaplen, a dropped packet, or a capture that started mid-connection has
//! bytes missing, and the two wrong things to do with a hole are equally wrong:
//! fill it (with zeroes, or with anything) and the examiner reads bytes the
//! machine never sent; close it (by joining the two sides) and the examiner
//! reads two fragments as adjacent when something unknown lay between them.
//! Either would put a sentence in a report that was never on the wire.
//!
//! So [`Stream::runs`] holds the contiguous pieces at their true offsets,
//! [`Stream::holes`] names what is between them, and
//! [`Stream::contiguous_prefix`] is the only view a parser is offered — the
//! bytes from the start of the stream up to the first thing missing. A parser
//! that wants more must say what it does about the hole.
//!
//! # An overlap that disagrees is a finding, not a tie to break
//!
//! Two segments can claim the same offsets with **different bytes**. Every
//! operating system resolves that some way, the ways differ, and the
//! disagreement is the mechanism behind a whole family of intrusion-detection
//! evasions: send the benign bytes so the sensor keeps them, send the hostile
//! bytes so the host keeps them. This module keeps the **first** bytes it was
//! given, counts the conflict, and records the offset it happened at — because
//! a reassembly that silently preferred one copy would hand an examiner one of
//! the two readings with nothing saying the other existed.
//!
//! # What it does not do
//!
//! It does not track the sequence space past 2 GiB in one direction
//! ([`MAX_STREAM_BYTES`] is far below that): a 32-bit sequence number wraps,
//! and deriving a stream offset across a wrap needs state this build does not
//! keep. A stream that reaches the ceiling is reported as truncated at the
//! offset it stopped, never as a stream that ended there.

use std::collections::{BTreeMap, BTreeSet};

use crate::decode::Decoded;
use crate::flows::{Direction, FlowKey};

/// Bytes one direction of one stream will hold.
///
/// A real HTTP exchange is kilobytes; a download is megabytes. This is the
/// ceiling at which a stream stops being assembled and says so, and it is
/// deliberately far below the 2 GiB at which a 32-bit sequence number's offset
/// stops being derivable without wrap tracking.
pub const MAX_STREAM_BYTES: u64 = 64 * 1024 * 1024;

/// Separate runs one direction will hold before it stops accepting new ones.
///
/// Reached by a capture whose packet loss is pathological, or by a sender
/// deliberately fragmenting to exhaust a reassembler. Past it the bytes are
/// counted and not placed, and the stream says so.
pub const MAX_RUNS: usize = 4096;

/// Streams one capture will assemble.
///
/// A count, so it bounds the table's bookkeeping, not its bytes — those are
/// [`MAX_TOTAL_BYTES`]'s. It was 4,096, and DFIR Madness Case 001's capture
/// showed what that costs: an RDP brute force from one host opened 28,249 of
/// the capture's 31,543 streams over about 38 minutes, the table was full at
/// 02:19:27, about four and a half minutes before the implant was downloaded
/// at 02:24:06, and neither the download nor any command-and-control session
/// was read. A stream that holds nothing costs its 144-byte record and its
/// 48-byte key plus the map's own overhead, so a full table of empty streams
/// is about 64 MiB — the same order as the flow table beside it — and the
/// capture record still says when it fills, and each refused conversation's
/// flow record says its bytes were not read.
pub const MAX_STREAMS: usize = 262_144;

/// Bytes the whole reassembly will hold, across every stream.
///
/// [`MAX_STREAM_BYTES`] bounds one stream and is no bound at all on the run: a
/// capture of a busy segment has thousands of streams, and the product of the
/// two ceilings is a quarter of a terabyte. This is the number that keeps a
/// capture of any size inside a working set an examiner's machine has — and
/// the streams cut by it say so, at the offset they were cut.
pub const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;

/// One direction of one TCP conversation, identified the way the flow table
/// identifies it so a stream and a flow can be put beside each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamKey {
    pub flow: FlowKey,
    /// Which endpoint sent these bytes. `Out` is the flow initiator's
    /// direction — whoever sent the first packet the capture holds, which on a
    /// capture that started mid-connection is not necessarily the client.
    pub direction: Direction,
}

/// A contiguous piece of a stream, at its offset from the first byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// Offset of the first byte, from the start of the stream.
    pub offset: u64,
    pub bytes: Vec<u8>,
}

impl Run {
    /// One past the last byte.
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.bytes.len() as u64)
    }
}

/// Bytes the capture does not hold, between the runs it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hole {
    pub offset: u64,
    pub length: u64,
}

/// Two segments claimed the same offsets with different bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conflict {
    /// Where the disagreement starts.
    pub offset: u64,
    /// How many bytes disagreed.
    pub length: u64,
}

/// Why a stream stopped being assembled, when it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamStop {
    /// Assembled to the end of what the capture held for it.
    EndOfCapture,
    /// [`MAX_STREAM_BYTES`] was reached. `at` is the offset from which nothing
    /// further was placed.
    ByteCeiling { at: u64 },
    /// [`MAX_RUNS`] separate pieces were already held.
    RunCeiling { at: u64 },
    /// The reassembly's own budget ([`MAX_TOTAL_BYTES`]) was exhausted by this
    /// stream and every other between them. Nothing above `at` was assembled,
    /// and those bytes are in the capture.
    TotalBudget { at: u64 },
}

/// One direction of one conversation, reassembled.
#[derive(Debug, Clone)]
pub struct Stream {
    pub key: StreamKey,
    /// The sequence number the offsets are relative to: the first byte of the
    /// stream.
    pub base_seq: u32,
    /// Whether that base came from a SYN. **`false` means the capture did not
    /// hold the handshake**, so offset 0 is the first byte this capture saw and
    /// not the first byte the connection carried — anything before it is
    /// missing and unmeasurable, which is a different statement from a hole.
    pub base_from_syn: bool,
    /// Contiguous pieces, ascending, disjoint and never adjacent.
    pub runs: Vec<Run>,
    /// Disagreements between segments claiming the same offsets, in the order
    /// they were met, capped at [`MAX_RUNS`].
    pub conflicts: Vec<Conflict>,
    /// Segments whose bytes repeated what was already held, byte for byte.
    pub retransmitted_bytes: u64,
    /// Segments that sat below the base: a retransmission of data sent before
    /// the capture began, or a sequence space that has wrapped. Counted and
    /// **not placed**, because this build cannot tell those two apart.
    pub segments_before_base: u64,
    /// Data-bearing segments accepted.
    pub segments: u64,
    /// Whether the sender's FIN was seen.
    pub fin_seen: bool,
    /// Whether a reset was seen on this direction.
    pub rst_seen: bool,
    pub stop: StreamStop,
}

impl Stream {
    fn new(key: StreamKey, base_seq: u32, base_from_syn: bool) -> Self {
        Self {
            key,
            base_seq,
            base_from_syn,
            runs: Vec::new(),
            conflicts: Vec::new(),
            retransmitted_bytes: 0,
            segments_before_base: 0,
            segments: 0,
            fin_seen: false,
            rst_seen: false,
            stop: StreamStop::EndOfCapture,
        }
    }

    /// Bytes actually held, which is not the stream's extent when there are
    /// holes.
    pub fn bytes_held(&self) -> u64 {
        self.runs
            .iter()
            .fold(0u64, |acc, r| acc.saturating_add(r.bytes.len() as u64))
    }

    /// One past the last byte any run holds.
    pub fn extent(&self) -> u64 {
        self.runs.last().map(Run::end).unwrap_or(0)
    }

    /// What is missing between the runs, and before the first one.
    ///
    /// A gap before offset 0 cannot exist: offset 0 is by definition the first
    /// byte this stream knows about. What can exist is a gap between runs, and
    /// — where the base came from a SYN and the first run starts above 0 — a
    /// gap at the very start of the connection.
    pub fn holes(&self) -> Vec<Hole> {
        let mut out = Vec::new();
        let mut cursor = 0u64;
        for run in &self.runs {
            if run.offset > cursor {
                out.push(Hole {
                    offset: cursor,
                    length: run.offset - cursor,
                });
            }
            cursor = run.end().max(cursor);
        }
        out
    }

    /// The bytes from the start of the stream to the first thing missing.
    ///
    /// **The only view a parser is offered.** Everything past the first hole is
    /// at an unknown distance from these bytes, so a parser reading across one
    /// would be reading two fragments as though they were adjacent.
    pub fn contiguous_prefix(&self) -> &[u8] {
        match self.runs.first() {
            Some(run) if run.offset == 0 => &run.bytes,
            _ => &[],
        }
    }

    /// Whether every byte between the first and the last is held, nothing
    /// disagreed, and no ceiling fired.
    ///
    /// Says nothing about whether the *connection* was captured whole: see
    /// [`Stream::base_from_syn`] and [`Stream::fin_seen`].
    pub fn is_contiguous(&self) -> bool {
        self.holes().is_empty()
            && self.conflicts.is_empty()
            && matches!(self.stop, StreamStop::EndOfCapture)
    }

    /// Place `bytes` at `offset`, keeping what is already there where the two
    /// disagree.
    /// Place what is new of `bytes`, and return how many bytes were placed.
    ///
    /// `budget_remaining` is what the whole reassembly has left to hold. It is
    /// checked per part rather than per segment, so a stream is cut exactly at
    /// the budget rather than a segment before it.
    fn place(
        &mut self,
        offset: u64,
        bytes: &[u8],
        config: &ReassemblyConfig,
        budget_remaining: u64,
    ) -> u64 {
        if bytes.is_empty() {
            return 0;
        }
        let end = offset.saturating_add(bytes.len() as u64);

        // Compare against what is held, piece by piece, and collect only the
        // parts that are genuinely new. Overlap that matches is a
        // retransmission; overlap that does not is a conflict, and the held
        // bytes win because they were there first.
        let mut new_parts: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut cursor = offset;
        for run in &self.runs {
            if run.end() <= cursor {
                continue;
            }
            if run.offset >= end {
                break;
            }
            if run.offset > cursor {
                let upto = run.offset.min(end);
                new_parts.push((cursor, slice_of(bytes, offset, cursor, upto)));
                cursor = upto;
            }
            // The overlapping part.
            let overlap_end = run.end().min(end);
            if overlap_end > cursor {
                let mine = slice_of(bytes, offset, cursor, overlap_end);
                let theirs = slice_of(&run.bytes, run.offset, cursor, overlap_end);
                if mine == theirs {
                    self.retransmitted_bytes =
                        self.retransmitted_bytes.saturating_add(mine.len() as u64);
                } else {
                    let differing = mine
                        .iter()
                        .zip(theirs.iter())
                        .filter(|(a, b)| a != b)
                        .count() as u64;
                    if self.conflicts.len() < config.max_runs {
                        self.conflicts.push(Conflict {
                            offset: cursor,
                            length: differing,
                        });
                    }
                }
                cursor = overlap_end;
            }
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            new_parts.push((cursor, slice_of(bytes, offset, cursor, end)));
        }

        let mut placed = 0u64;
        for (at, part) in new_parts {
            if part.is_empty() {
                continue;
            }
            if self.bytes_held().saturating_add(part.len() as u64) > config.max_stream_bytes {
                self.stop = StreamStop::ByteCeiling { at };
                return placed;
            }
            if self.runs.len() >= config.max_runs && !self.touches_a_run(at, part.len() as u64) {
                self.stop = StreamStop::RunCeiling { at };
                return placed;
            }
            // The reassembly's own budget. A part that only partly fits is
            // placed as far as it fits: those bytes are evidence, and the
            // offset they stop at is stated.
            let room = budget_remaining.saturating_sub(placed);
            if (part.len() as u64) > room {
                let keep = room as usize;
                if keep > 0 {
                    self.insert(at, part[..keep].to_vec());
                    placed = placed.saturating_add(keep as u64);
                }
                self.stop = StreamStop::TotalBudget {
                    at: at.saturating_add(keep as u64),
                };
                return placed;
            }
            placed = placed.saturating_add(part.len() as u64);
            self.insert(at, part);
        }
        placed
    }

    /// Whether a piece at `[at, at+len)` would merge with a run it touches,
    /// rather than becoming a new one.
    fn touches_a_run(&self, at: u64, len: u64) -> bool {
        let end = at.saturating_add(len);
        self.runs
            .iter()
            .any(|run| run.offset <= end && at <= run.end())
    }

    /// Insert a piece that is known not to overlap anything held, merging it
    /// with whatever it touches.
    fn insert(&mut self, at: u64, bytes: Vec<u8>) {
        let position = self
            .runs
            .iter()
            .position(|run| run.offset > at)
            .unwrap_or(self.runs.len());
        self.runs.insert(position, Run { offset: at, bytes });

        // Merge forward from the run before the one just inserted, so a piece
        // that closes a gap joins both sides.
        let from = position.saturating_sub(1);
        let mut i = from;
        while i + 1 < self.runs.len() {
            let joins = self.runs[i].end() == self.runs[i + 1].offset;
            if joins {
                let next = self.runs.remove(i + 1);
                self.runs[i].bytes.extend_from_slice(&next.bytes);
            } else {
                i += 1;
            }
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        let holes = self.holes();
        serde_json::json!({
            "base_seq": self.base_seq,
            "base_from_syn": self.base_from_syn,
            "base_meaning": if self.base_from_syn {
                "Offset 0 is the connection's first byte: the capture holds the handshake."
            } else {
                "Offset 0 is the FIRST BYTE THIS CAPTURE SAW, not the connection's first byte. \
                 The capture does not hold the handshake, so whatever was sent before it is \
                 missing and its size is not knowable from these bytes -- which is a different \
                 statement from a hole, whose size is known."
            },
            "bytes_held": self.bytes_held(),
            "extent": self.extent(),
            "runs": self.runs.len(),
            "holes": holes.iter().map(|h| serde_json::json!({
                "offset": h.offset,
                "length": h.length,
            })).collect::<Vec<_>>(),
            "holes_total_bytes": holes.iter().fold(0u64, |a, h| a.saturating_add(h.length)),
            "conflicts": self.conflicts.iter().map(|c| serde_json::json!({
                "offset": c.offset,
                "length": c.length,
            })).collect::<Vec<_>>(),
            "conflict_meaning":
                "Two segments claimed these offsets with DIFFERENT bytes. The bytes held are \
                 the ones that arrived first; the others are not in this stream. Operating \
                 systems resolve this differently, which is the mechanism behind a family of \
                 sensor evasions, so it is reported rather than resolved.",
            "retransmitted_bytes": self.retransmitted_bytes,
            "segments": self.segments,
            "segments_before_base": self.segments_before_base,
            "fin_seen": self.fin_seen,
            "rst_seen": self.rst_seen,
            "stop": match &self.stop {
                StreamStop::EndOfCapture => serde_json::json!("end_of_capture"),
                StreamStop::ByteCeiling { at } => serde_json::json!({
                    "reason": "byte_ceiling", "at": at,
                }),
                StreamStop::RunCeiling { at } => serde_json::json!({
                    "reason": "run_ceiling", "at": at,
                }),
                StreamStop::TotalBudget { at } => serde_json::json!({
                    "reason": "total_budget", "at": at,
                }),
            },
            "contiguous": self.is_contiguous(),
        })
    }
}

/// `bytes` starts at `base`; return the part covering `[from, to)`.
fn slice_of(bytes: &[u8], base: u64, from: u64, to: u64) -> Vec<u8> {
    let start = from.saturating_sub(base) as usize;
    let end = to.saturating_sub(base) as usize;
    bytes
        .get(start..end.min(bytes.len()))
        .unwrap_or(&[])
        .to_vec()
}

/// Ceilings one reassembly observes.
#[derive(Debug, Clone)]
pub struct ReassemblyConfig {
    pub max_stream_bytes: u64,
    pub max_runs: usize,
    pub max_streams: usize,
    /// Bytes every stream in this reassembly may hold between them.
    pub max_total_bytes: u64,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            max_stream_bytes: MAX_STREAM_BYTES,
            max_runs: MAX_RUNS,
            max_streams: MAX_STREAMS,
            max_total_bytes: MAX_TOTAL_BYTES,
        }
    }
}

/// Assembles every TCP stream in one capture.
#[derive(Debug)]
pub struct Reassembler {
    streams: BTreeMap<StreamKey, Stream>,
    config: ReassemblyConfig,
    /// Segments on a stream the table had no room for.
    pub segments_beyond_cap: u64,
    /// The conversations at least one of whose directions the table had no
    /// room for, so the flow record can say its bytes were not read rather
    /// than say nothing. Bounded by the flow table's own cap: a key lands here
    /// only once, and only for a flow the capture holds.
    refused_flows: BTreeSet<FlowKey>,
    /// Whether [`ReassemblyConfig::max_streams`] fired.
    pub stream_cap_reached: bool,
    /// Bytes held across every stream, which is what the budget bounds.
    pub bytes_held: u64,
    /// Whether [`ReassemblyConfig::max_total_bytes`] was reached.
    pub total_budget_reached: bool,
    /// Segments that arrived with no budget left to hold them.
    pub segments_beyond_total_budget: u64,
}

impl Reassembler {
    pub fn new(config: ReassemblyConfig) -> Self {
        Self {
            streams: BTreeMap::new(),
            config,
            segments_beyond_cap: 0,
            refused_flows: BTreeSet::new(),
            stream_cap_reached: false,
            bytes_held: 0,
            total_budget_reached: false,
            segments_beyond_total_budget: 0,
        }
    }

    /// Offer one decoded TCP segment and its captured payload.
    ///
    /// `payload` is what the frame actually held, which a snaplen can make
    /// shorter than the segment claimed. Only the bytes present are placed:
    /// the rest of that segment is a hole like any other, because bytes that
    /// were not captured are not bytes.
    pub fn offer(
        &mut self,
        flow: FlowKey,
        direction: Direction,
        decoded: &Decoded,
        payload: &[u8],
    ) {
        let Some(seq) = decoded.tcp_seq else {
            return;
        };
        let flags = decoded.tcp_flags.unwrap_or(0);
        let key = StreamKey { flow, direction };

        let stream = match self.streams.get_mut(&key) {
            Some(stream) => stream,
            None => {
                // A stream is opened by a SYN or by data. A bare ACK opens
                // nothing: its sequence number is the next byte the sender
                // intends, and taking that as a base would put the stream's
                // first data byte at a negative offset.
                let syn = flags & TCP_SYN != 0;
                if !syn && payload.is_empty() {
                    return;
                }
                if self.streams.len() >= self.config.max_streams {
                    self.stream_cap_reached = true;
                    self.segments_beyond_cap = self.segments_beyond_cap.saturating_add(1);
                    self.refused_flows.insert(flow);
                    return;
                }
                // A SYN consumes one sequence number and carries no data, so
                // the first data byte is at `seq + 1`.
                let base = if syn { seq.wrapping_add(1) } else { seq };
                self.streams
                    .entry(key)
                    .or_insert_with(|| Stream::new(key, base, syn))
            }
        };

        if flags & TCP_FIN != 0 {
            stream.fin_seen = true;
        }
        if flags & TCP_RST != 0 {
            stream.rst_seen = true;
        }
        if payload.is_empty() {
            return;
        }

        // Where these bytes sit in the stream. The distance is signed in the
        // 32-bit sequence space: a negative one is a retransmission of data
        // sent before this capture began, or a space that has wrapped, and
        // this build cannot tell those apart — so it counts the segment and
        // places nothing.
        let distance = seq.wrapping_sub(stream.base_seq) as i32;
        if distance < 0 {
            stream.segments_before_base = stream.segments_before_base.saturating_add(1);
            return;
        }
        stream.segments = stream.segments.saturating_add(1);
        let config = self.config.clone();
        let remaining = config.max_total_bytes.saturating_sub(self.bytes_held);
        let placed = stream.place(distance as u64, payload, &config, remaining);
        self.bytes_held = self.bytes_held.saturating_add(placed);
        if matches!(stream.stop, StreamStop::TotalBudget { .. }) {
            self.total_budget_reached = true;
            self.segments_beyond_total_budget = self.segments_beyond_total_budget.saturating_add(1);
        }
    }

    /// Every stream assembled, in flow order.
    pub fn finish(self) -> Vec<Stream> {
        self.streams.into_values().collect()
    }

    /// The conversations the table refused a direction of, taken out so they
    /// can travel on past [`Reassembler::finish`].
    pub fn take_refused_flows(&mut self) -> BTreeSet<FlowKey> {
        std::mem::take(&mut self.refused_flows)
    }

    /// Whether a direction of this conversation carried a segment the stream
    /// table had no room for.
    pub fn was_refused(&self, flow: &FlowKey) -> bool {
        self.refused_flows.contains(flow)
    }

    /// Streams assembled so far.
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// One stream, for a caller that knows which it wants.
    pub fn stream(&self, key: &StreamKey) -> Option<&Stream> {
        self.streams.get(key)
    }
}

/// Every stream by its key.
///
/// Built once by each caller that needs to find a conversation's two
/// directions. A scan per flow per direction is O(flows x streams), and both
/// numbers are controlled by whoever wrote the capture: half a million flows
/// against four thousand streams is ten billion comparisons out of a file
/// that parses in a second.
pub fn index_streams(streams: &[Stream]) -> BTreeMap<StreamKey, &Stream> {
    streams.iter().map(|s| (s.key, s)).collect()
}

/// One direction of one conversation, out of such an index.
pub fn stream_of<'a>(
    index: &BTreeMap<StreamKey, &'a Stream>,
    flow: FlowKey,
    direction: Direction,
) -> Option<&'a Stream> {
    index.get(&StreamKey { flow, direction }).copied()
}
