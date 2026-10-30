//! Multi-member expansion for gzip and bzip2 (HUNT-169).
//!
//! Both formats allow a file to be a series of independently compressed
//! members laid end to end: RFC 1952 says so of gzip, `bzip2` documents the
//! same for its streams, and real files take that shape all the time — logs
//! rotated with `cat a.gz b.gz`, `pbzip2` output, the Wikipedia dumps. `zcat`
//! and `bzcat` print every member. A single-member decoder stops at the first
//! one and returns end-of-file, so the child was the first member published as
//! the whole file.
//!
//! The library multi-member decoders are not used either, because they treat
//! anything after the last member as the start of another one and fail on it —
//! which would turn `gzip`'s "decompression OK, trailing garbage ignored" into
//! an archive we refused whole. Instead this walks the members itself: after
//! each one it looks at the next bytes, decodes another member if the format's
//! magic is there, and otherwise stops and remembers exactly where, so the
//! caller can say how many bytes followed the last member and were never
//! decoded.

use seance_core::{
    data_source::{DataSource, SourceCursor},
    io::read_full,
};
use std::io::{self, BufRead, BufReader, Read};
use std::sync::Arc;

/// A buffered reader that counts the bytes its consumer has taken from it.
///
/// The `bufread` decoders consume exactly one member's bytes and leave the rest
/// in the buffer, so this count is the offset, in the compressed input, at
/// which the member just decoded ended.
pub(crate) struct Counting<R> {
    inner: R,
    consumed: u64,
}

impl<R: BufRead> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = {
            let avail = self.inner.fill_buf()?;
            let n = avail.len().min(buf.len());
            buf[..n].copy_from_slice(&avail[..n]);
            n
        };
        self.consume(n);
        Ok(n)
    }
}

impl<R: BufRead> BufRead for Counting<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.consumed += amt as u64;
        self.inner.consume(amt);
    }
}

/// The compressed input a member decoder reads from.
pub(crate) type Input = Counting<BufReader<SourceCursor>>;

/// A decoder that reads exactly one member and hands its input back.
pub(crate) trait MemberDecoder: Read + Sized {
    fn open(input: Input) -> Self;
    fn finish(self) -> Input;
}

impl MemberDecoder for flate2::bufread::GzDecoder<Input> {
    fn open(input: Input) -> Self {
        flate2::bufread::GzDecoder::new(input)
    }
    fn finish(self) -> Input {
        self.into_inner()
    }
}

impl MemberDecoder for ::bzip2::bufread::BzDecoder<Input> {
    fn open(input: Input) -> Self {
        ::bzip2::bufread::BzDecoder::new(input)
    }
    fn finish(self) -> Input {
        self.into_inner()
    }
}

/// A reader over every member of a gzip or bzip2 file, in order.
pub(crate) struct MemberChain<D> {
    source: Arc<dyn DataSource>,
    magic: &'static [u8],
    current: Option<D>,
    idle: Option<Input>,
    members: u64,
    /// Where the member being decoded began.
    member_start: u64,
    /// The compressed offset at which the walk stopped, once it has.
    end: Option<u64>,
}

/// What the walk established about the compressed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemberOutcome {
    /// Members decoded to completion.
    pub members: u64,
    /// Offset in the compressed input just past the last member decoded.
    pub end_offset: u64,
    /// Bytes from `end_offset` to the end of the input: present, not a member,
    /// and never decoded.
    pub trailing_bytes: u64,
}

impl<D: MemberDecoder> MemberChain<D> {
    pub(crate) fn new(source: Arc<dyn DataSource>, magic: &'static [u8]) -> Self {
        let input = Counting {
            inner: BufReader::with_capacity(64 * 1024, SourceCursor::new(source.clone())),
            consumed: 0,
        };
        Self {
            source,
            magic,
            current: None,
            idle: Some(input),
            members: 0,
            member_start: 0,
            end: None,
        }
    }

    /// The outcome once the chain has been read to its end.
    pub(crate) fn outcome(&self) -> MemberOutcome {
        let end_offset = self.end.unwrap_or(0);
        MemberOutcome {
            members: self.members,
            end_offset,
            trailing_bytes: self.source.size().saturating_sub(end_offset),
        }
    }

    /// Whether the next member's magic sits at `offset`.
    fn member_starts_at(&self, offset: u64) -> bool {
        let mut buf = vec![0u8; self.magic.len()];
        read_full(self.source.as_ref(), offset, &mut buf) == buf.len() && buf == self.magic
    }
}

impl<D: MemberDecoder> Read for MemberChain<D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.end.is_some() {
                return Ok(0);
            }
            if let Some(decoder) = self.current.as_mut() {
                let n = decoder.read(buf)?;
                if n > 0 || buf.is_empty() {
                    return Ok(n);
                }
                // This member is complete (its trailer was verified by the
                // decoder); take the input back and look at what follows.
                let input = self.current.take().map(D::finish);
                self.members += 1;
                self.idle = input;
            }
            let Some(offset) = self.idle.as_ref().map(|i| i.consumed) else {
                return Ok(0);
            };
            // The first member is always attempted: whether the file is ours
            // at all is the caller's question, answered from the magic before
            // this runs. After it, another member is decoded only where the
            // magic says one begins; anything else ends the walk here.
            if self.members > 0 && !self.member_starts_at(offset) {
                self.end = Some(offset);
                return Ok(0);
            }
            // A member that ended without consuming a byte would be decoded
            // again at the same offset forever. No decoder here does that, but
            // the loop must not depend on it.
            if self.members > 0 && offset == self.member_start {
                self.end = Some(offset);
                return Ok(0);
            }
            self.member_start = offset;
            if let Some(input) = self.idle.take() {
                self.current = Some(D::open(input));
            }
        }
    }
}

/// Whether every byte of `source` in `[offset, end)` is zero.
///
/// Zero padding after the last member — a tape block or a block-device write —
/// cannot hold a member, so it is counted but not called a gap. Reads in
/// chunks, and a short read is treated as "not known to be zero".
pub(crate) fn all_zero(source: &dyn DataSource, offset: u64, end: u64) -> bool {
    let mut buf = vec![0u8; 64 * 1024];
    let mut at = offset;
    while at < end {
        let want = ((end - at) as usize).min(buf.len());
        let got = read_full(source, at, &mut buf[..want]);
        if got != want || buf[..want].iter().any(|&b| b != 0) {
            return false;
        }
        at += want as u64;
    }
    true
}

/// Record on an expanded child how many members were decoded and, when bytes
/// followed the last one, where they start and how many there are.
///
/// Non-zero trailing bytes also mark the child incomplete: they are not a
/// member, but they may be the remains of one whose header was overwritten,
/// and the child cannot be said to be the whole of what the file held.
pub(crate) fn stamp_members(
    metadata: &mut serde_json::Value,
    source: &dyn DataSource,
    format: &str,
    outcome: MemberOutcome,
) {
    let Some(obj) = metadata.as_object_mut() else {
        return;
    };
    obj.insert(
        "compressed_members".to_string(),
        serde_json::json!(outcome.members),
    );
    if outcome.trailing_bytes == 0 {
        return;
    }
    let zero = all_zero(source, outcome.end_offset, source.size());
    obj.insert(
        "trailing_bytes_after_last_member".to_string(),
        serde_json::json!(outcome.trailing_bytes),
    );
    obj.insert(
        "trailing_bytes_offset".to_string(),
        serde_json::json!(outcome.end_offset),
    );
    obj.insert(
        "trailing_bytes_all_zero".to_string(),
        serde_json::json!(zero),
    );
    if !zero {
        let detail = format!(
            "{} bytes follow the last {format} member (which ends at offset {}) and do not \
             begin another member, so they were not decoded. They may be unrelated data or \
             the remains of a damaged member; this content is every member that could be \
             decoded, not necessarily everything the file held",
            outcome.trailing_bytes, outcome.end_offset
        );
        obj.insert(
            seance_core::io::CONTENT_INCOMPLETE.to_string(),
            serde_json::json!(true),
        );
        obj.insert(
            seance_core::io::CONTENT_INCOMPLETE_REASON.to_string(),
            serde_json::json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
        );
        obj.insert(
            "content_incomplete_detail".to_string(),
            serde_json::json!(detail),
        );
    }
}
