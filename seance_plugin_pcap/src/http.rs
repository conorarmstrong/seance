//! HTTP over a reassembled stream: what was asked for, what came back
//! (`ROADMAP` §4.3 stage 2).
//!
//! # Recognised by its own first bytes, never by a port
//!
//! A request begins with a method token, a target and `HTTP/1.`; a response
//! begins with `HTTP/1.`. That is what this module looks for, on **any** TCP
//! stream. Keying off port 80 would miss every C2 that talks HTTP on 8443 and
//! would try to parse the binary protocol that happens to be on 80 — and the
//! first of those is the case an examiner is usually looking for.
//!
//! # It parses only what the capture holds contiguously
//!
//! The reassembler hands over the bytes before the first gap and nothing else
//! ([`crate::reassemble::Stream::contiguous_prefix`]). Everything here works
//! on that prefix, so no message is ever parsed across a hole: a header read
//! from two fragments that were not adjacent would be a header nobody sent.
//! Where the prefix ends mid-message the message is reported as **partial**,
//! carrying what was read, and never as a message that ended there.
//!
//! # The pairing of a response to a request is an assumption, and it says so
//!
//! HTTP/1.1 allows several requests on one connection, answered in order, so
//! the *n*th response answers the *n*th request. That is what this module
//! assumes and it is right for well-behaved traffic. It is **not** knowable
//! from the bytes when either direction has a gap in it — the missing bytes
//! may have held a whole request — so every transaction carries how it was
//! paired, and a stream with a hole marks its pairings unreliable.
//!
//! # What it does not read
//!
//! HTTP/2 and HTTP/3 (binary framing, and in practice inside TLS), and
//! anything inside TLS at all: the certificate and the server name are
//! reachable and are `crate::tls`'s subject, the body is not. A `CONNECT`
//! tunnel's payload is likewise not HTTP and is not parsed as any.

use std::collections::BTreeMap;

/// Header lines one message will hold. A real message has a dozen; a hostile
/// one can claim thousands.
pub const MAX_HEADERS: usize = 256;

/// Bytes one header line may occupy.
pub const MAX_HEADER_LINE: usize = 8 * 1024;

/// HTTP/2's connection preface (RFC 9113 §3.4). A client speaking HTTP/2
/// sends exactly these bytes first, which makes an HTTP/2 stream recognisable
/// even though this build does not read it — and saying "HTTP/2 was here and
/// was not read" is a different statement from saying nothing.
pub const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Bytes of one message's whole header block. [`MAX_HEADERS`] bounds the
/// number of names and [`MAX_HEADER_LINE`] bounds one line; without this, a
/// single name repeated ten thousand times bounds nothing at all, because a
/// repeat grows one value instead of adding a name.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Messages parsed from one stream. Keep-alive carries a handful; a pipelined
/// scan carries more, and past this the stream says so.
pub const MAX_MESSAGES_PER_STREAM: usize = 256;

/// Bytes of one message body carried on the record, and handed on as an
/// artifact. Past it the body is reported by its length and truncated, never
/// silently shortened.
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Which kind of message this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Request,
    Response,
}

/// How a message's body ended, which is the difference between a body an
/// examiner can rely on and a body that is a prefix of one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyEnd {
    /// `Content-Length` bytes were present.
    LengthSatisfied { declared: u64 },
    /// `Content-Length` declared more than the stream held.
    LengthShort { declared: u64, present: u64 },
    /// The message declared more than one body length and they do not agree.
    /// RFC 9110 §8.6 calls that unrecoverable, and it is the signature of a
    /// request-smuggling attempt: two devices in the path frame the stream
    /// differently on purpose. No framing is chosen and no body is claimed —
    /// picking one would hand a reader one of the two readings with nothing
    /// saying the other existed.
    LengthDisagreement { declared: String },
    /// A chunked body whose terminating zero-length chunk was read.
    ChunkedComplete,
    /// A chunked body the stream ended inside.
    ChunkedTruncated { present: u64 },
    /// A chunked body with a chunk-size line this build could not read.
    ChunkedMalformed { at: u64 },
    /// Neither `Content-Length` nor chunked framing: the body runs to the end
    /// of the stream, which is only a complete body if the connection closed.
    ToEndOfStream { present: u64, fin_seen: bool },
    /// The message declared no body and carries none.
    None,
}

impl BodyEnd {
    /// Whether the body on the record is the whole body the message carried.
    pub fn is_whole(&self) -> bool {
        match self {
            BodyEnd::LengthSatisfied { .. } | BodyEnd::ChunkedComplete | BodyEnd::None => true,
            BodyEnd::ToEndOfStream { fin_seen, .. } => *fin_seen,
            BodyEnd::LengthShort { .. }
            | BodyEnd::ChunkedTruncated { .. }
            | BodyEnd::ChunkedMalformed { .. }
            | BodyEnd::LengthDisagreement { .. } => false,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            BodyEnd::LengthSatisfied { .. } => "length_satisfied",
            BodyEnd::LengthShort { .. } => "length_short",
            BodyEnd::LengthDisagreement { .. } => "length_disagreement",
            BodyEnd::ChunkedComplete => "chunked_complete",
            BodyEnd::ChunkedTruncated { .. } => "chunked_truncated",
            BodyEnd::ChunkedMalformed { .. } => "chunked_malformed",
            BodyEnd::ToEndOfStream { .. } => "to_end_of_stream",
            BodyEnd::None => "none",
        }
    }
}

/// One HTTP message read out of a stream.
#[derive(Debug, Clone)]
pub struct Message {
    pub kind: Kind,
    /// Offset in the stream at which the start line began.
    pub offset: u64,
    /// `GET`, `POST`, … for a request.
    pub method: Option<String>,
    /// The request target exactly as it was sent, which may be a path, an
    /// absolute URL (a proxy request) or an authority (`CONNECT`).
    pub target: Option<String>,
    /// `HTTP/1.1`, as stated.
    pub version: Option<String>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    /// Header names lower-cased — they are case-insensitive by RFC — with
    /// their values as sent. A repeated header keeps every value, joined with
    /// `, `, because dropping one loses evidence.
    pub headers: BTreeMap<String, String>,
    /// Whether the header block ended with a blank line. `false` means the
    /// stream ran out first, so the headers are a prefix of the message's.
    pub headers_complete: bool,
    /// Header lines beyond [`MAX_HEADERS`] or [`MAX_HEADER_BYTES`], or longer
    /// than [`MAX_HEADER_LINE`], which were not parsed.
    pub headers_dropped: usize,
    /// Continuation lines joined to the header before them (RFC 9112's
    /// obs-fold). Counted because the form is deprecated and a message using
    /// it is worth a second look.
    pub folded_headers: usize,
    /// The body bytes present in the stream, capped at [`MAX_BODY_BYTES`].
    pub body: Vec<u8>,
    /// Whether the body on this record was cut by that cap.
    pub body_capped: bool,
    pub body_end: BodyEnd,
}

impl Message {
    /// One header, by its lower-case name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// What the message says its body is, which is not what the body is.
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Whether everything this message declared was read, AND everything read
    /// is on this record: a body cut at this build's ceiling is not a whole
    /// body, however completely the stream held it.
    pub fn is_whole(&self) -> bool {
        self.headers_complete
            && self.headers_dropped == 0
            && self.body_end.is_whole()
            && !self.body_capped
    }

    /// Serializable form for artifact metadata. The body is **not** here: it
    /// is handed on as its own artifact so the ordinary parsers, the carver and
    /// the search index see it.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": match self.kind { Kind::Request => "request", Kind::Response => "response" },
            "offset": self.offset,
            "method": self.method,
            "target": self.target,
            "version": self.version,
            "status": self.status,
            "reason": self.reason,
            "host": self.header("host"),
            "user_agent": self.header("user-agent"),
            "content_type": self.content_type(),
            "content_length_declared": self.header("content-length"),
            "content_encoding": self.header("content-encoding"),
            "referer": self.header("referer"),
            "server": self.header("server"),
            "location": self.header("location"),
            "headers": self.headers.iter().map(|(k, v)| (k.clone(), serde_json::json!(v)))
                .collect::<serde_json::Map<_, _>>(),
            "headers_complete": self.headers_complete,
            "headers_dropped": self.headers_dropped,
            "folded_headers": self.folded_headers,
            "body_bytes": self.body.len(),
            "body_capped": self.body_capped,
            "body_end": self.body_end.as_str(),
            "body_is_whole": self.body_end.is_whole(),
            "complete": self.is_whole(),
        })
    }
}

/// Every message read from one stream, and why reading stopped.
#[derive(Debug, Clone, Default)]
pub struct StreamMessages {
    pub messages: Vec<Message>,
    /// Bytes of the readable prefix that were not consumed by a message: a
    /// message this build could not parse, or the tail of a truncated one.
    pub trailing_unparsed: u64,
    /// Whether [`MAX_MESSAGES_PER_STREAM`] fired.
    pub message_cap_reached: bool,
    /// Whether reading stopped because a start line was longer than
    /// [`MAX_HEADER_LINE`]. A target as long as the stream is not a target
    /// this build puts on a record, and the refusal is reported rather than
    /// left as bytes nobody explained.
    pub start_line_too_long: bool,
    /// Whether this direction begins with HTTP/2's connection preface.
    ///
    /// Counted rather than passed over in silence. HTTP/2 is most of the web,
    /// this build does not read it, and a capture full of it would otherwise
    /// produce no HTTP records and nothing anywhere saying HTTP/2 was
    /// present — which is "could not look" rendering as "not there", the one
    /// thing this project refuses to do. Compare an undecodable LINKTYPE,
    /// which leaves a refusal record naming the number.
    pub http2_preface: bool,
}

/// Whether these bytes begin an HTTP/1.x message, and which kind.
///
/// Deliberately strict: a start line this does not recognise is not HTTP as
/// far as this module is concerned, and a stream of some other protocol must
/// not be reported as a malformed HTTP one.
pub fn sniff(bytes: &[u8]) -> Option<Kind> {
    if bytes.starts_with(b"HTTP/1.") {
        return Some(Kind::Response);
    }
    // A request line: TOKEN SP target SP HTTP/1.x. The method is checked
    // against the registered set rather than "any token", because any token
    // matches the first word of a great deal of binary traffic.
    const METHODS: [&[u8]; 9] = [
        b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"TRACE", b"CONNECT", b"PATCH",
    ];
    let end = bytes.len().min(MAX_HEADER_LINE);
    let line = &bytes[..end];
    for method in METHODS {
        if line.starts_with(method) && line.get(method.len()) == Some(&b' ') {
            // `HTTP/1.` must appear on the same line for this to be a request.
            let upto = line
                .iter()
                .position(|b| *b == b'\r' || *b == b'\n')
                .unwrap_or(line.len());
            if line[..upto].windows(7).any(|w| w == b"HTTP/1.") {
                return Some(Kind::Request);
            }
        }
    }
    None
}

/// Read every HTTP message in `prefix`, which must be the stream's contiguous
/// prefix.
///
/// `fin_seen` is whether the sender's FIN was captured, which is the only
/// thing that makes a body with no declared length a complete body.
pub fn parse_stream(prefix: &[u8], fin_seen: bool) -> StreamMessages {
    parse_stream_with_methods(prefix, fin_seen, &[])
}

/// Read one direction, knowing the methods of the requests its messages
/// answer.
///
/// `methods[n]` is the method of the request the *n*th message here answers.
/// It matters because a response's framing is not always in its own headers: a
/// response to `HEAD` carries no body however long it says its representation
/// is, and reading one as if it did takes the next response as this one's body
/// and loses every message after it. A direction read without the methods
/// (an empty slice) frames each response from its own headers alone, which is
/// the best that can be done and is why the two are separate calls.
pub fn parse_stream_with_methods(
    prefix: &[u8],
    fin_seen: bool,
    methods: &[&str],
) -> StreamMessages {
    let mut out = StreamMessages {
        http2_preface: prefix.starts_with(HTTP2_PREFACE),
        ..StreamMessages::default()
    };
    let mut at = 0usize;
    while at < prefix.len() {
        if sniff(&prefix[at..]).is_none() {
            break;
        }
        if out.messages.len() >= MAX_MESSAGES_PER_STREAM {
            out.message_cap_reached = true;
            break;
        }
        // The start line is bounded like every header line. Without this a
        // crafted target is the whole stream, and it is copied into the
        // record, the URL and the decoded query.
        match read_line(&prefix[at..], 0) {
            Some((line, _)) if line.len() > MAX_HEADER_LINE => {
                out.start_line_too_long = true;
                break;
            }
            _ => {}
        }
        let answering = methods.get(out.messages.len()).copied();
        let Some((message, consumed)) =
            parse_message(&prefix[at..], at as u64, fin_seen, answering)
        else {
            break;
        };
        at = at.saturating_add(consumed.max(1));
        let whole = message.is_whole();
        out.messages.push(message);
        // A message the stream ended inside is the last one there can be.
        if !whole {
            break;
        }
    }
    out.trailing_unparsed = prefix.len().saturating_sub(at) as u64;
    out
}

/// Parse one message at the start of `bytes`, returning it and how many bytes
/// it consumed.
fn parse_message(
    bytes: &[u8],
    offset: u64,
    fin_seen: bool,
    answering: Option<&str>,
) -> Option<(Message, usize)> {
    let kind = sniff(bytes)?;
    let (start_line, mut cursor) = read_line(bytes, 0)?;
    let mut message = Message {
        kind,
        offset,
        method: None,
        target: None,
        version: None,
        status: None,
        reason: None,
        headers: BTreeMap::new(),
        headers_complete: false,
        headers_dropped: 0,
        folded_headers: 0,
        body: Vec::new(),
        body_capped: false,
        body_end: BodyEnd::None,
    };
    match kind {
        Kind::Request => {
            let mut parts = start_line.splitn(3, |b| *b == b' ');
            message.method = parts.next().map(lossy);
            message.target = parts.next().map(lossy);
            message.version = parts.next().map(|v| lossy(trim(v)));
        }
        Kind::Response => {
            let mut parts = start_line.splitn(3, |b| *b == b' ');
            message.version = parts.next().map(lossy);
            message.status = parts
                .next()
                .and_then(|s| std::str::from_utf8(s).ok())
                .and_then(|s| s.trim().parse::<u16>().ok());
            message.reason = parts.next().map(|r| lossy(trim(r)));
        }
    }

    // Headers, to the blank line. `last_name` is kept so a continuation line
    // can be joined to the header it continues.
    let mut header_bytes = 0usize;
    let mut last_name: Option<String> = None;
    loop {
        let Some((line, next)) = read_line(bytes, cursor) else {
            // The stream ended inside the header block.
            return Some((message, bytes.len()));
        };
        cursor = next;
        if line.is_empty() {
            message.headers_complete = true;
            break;
        }
        header_bytes = header_bytes.saturating_add(line.len());
        if message.headers.len() >= MAX_HEADERS
            || line.len() > MAX_HEADER_LINE
            || header_bytes > MAX_HEADER_BYTES
        {
            message.headers_dropped = message.headers_dropped.saturating_add(1);
            continue;
        }
        // A line beginning with a space or a tab continues the header before
        // it (RFC 9112 §5.2's obs-fold), and the fold becomes one space. Read
        // as its own line it would either be dropped as a header with no
        // colon or — worse, where it happens to contain one — become a header
        // nobody sent.
        if matches!(line.first(), Some(b' ' | b'\t')) {
            if let Some(name) = last_name.as_deref() {
                let continuation = lossy(trim(line));
                if let Some(held) = message.headers.get_mut(name) {
                    held.push(' ');
                    held.push_str(&continuation);
                }
                message.folded_headers = message.folded_headers.saturating_add(1);
                continue;
            }
            // A fold with nothing before it continues nothing.
            message.headers_dropped = message.headers_dropped.saturating_add(1);
            continue;
        }
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            // A header line with no colon: not a header. Counted, not guessed.
            message.headers_dropped = message.headers_dropped.saturating_add(1);
            continue;
        };
        let name = lossy(&line[..colon]).to_ascii_lowercase();
        let value = lossy(trim(&line[colon + 1..]));
        last_name = Some(name.clone());
        message
            .headers
            .entry(name)
            .and_modify(|held| {
                // A repeated header keeps both values: dropping one loses
                // evidence, and which one a server used is not knowable here.
                held.push_str(", ");
                held.push_str(&value);
            })
            .or_insert(value);
    }

    if !message.headers_complete {
        return Some((message, bytes.len()));
    }

    // A response to some requests, and with some statuses, carries no body
    // whatever its headers say (RFC 9112 §6.3). Framing one from its headers
    // takes the next response as this one's body and loses every message
    // after it.
    if kind == Kind::Response && !can_carry_a_body(message.status, answering) {
        message.body_end = BodyEnd::None;
        return Some((message, cursor));
    }

    // The body. Which framing applies is the message's own statement.
    let chunked = message
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let declared = match content_length(message.header("content-length")) {
        Declared::Length(length) => Some(length),
        Declared::None => None,
        // Two lengths that disagree: no framing is chosen, because choosing
        // one is exactly what the two devices in a smuggling attack do
        // differently.
        Declared::Disagreement(text) => {
            message.body_end = BodyEnd::LengthDisagreement { declared: text };
            return Some((message, cursor));
        }
    };
    let available = bytes.len().saturating_sub(cursor);

    if chunked {
        let (body, end, consumed) = read_chunked(&bytes[cursor..]);
        message.body_capped = body.len() >= MAX_BODY_BYTES;
        message.body = body;
        message.body_end = end;
        return Some((message, cursor.saturating_add(consumed)));
    }
    if let Some(declared) = declared {
        let want = usize::try_from(declared).unwrap_or(usize::MAX);
        let take = want.min(available).min(MAX_BODY_BYTES);
        message.body = bytes[cursor..cursor + take].to_vec();
        message.body_capped = take < want.min(available);
        message.body_end = if (available as u64) >= declared {
            BodyEnd::LengthSatisfied { declared }
        } else {
            BodyEnd::LengthShort {
                declared,
                present: available as u64,
            }
        };
        let consumed = cursor.saturating_add(want.min(available));
        return Some((message, consumed));
    }
    // No framing. A request with no body declaration has none; a response
    // with none carries the rest of the connection.
    match kind {
        Kind::Request => {
            message.body_end = BodyEnd::None;
            Some((message, cursor))
        }
        Kind::Response => {
            let take = available.min(MAX_BODY_BYTES);
            message.body = bytes[cursor..cursor + take].to_vec();
            message.body_capped = take < available;
            message.body_end = BodyEnd::ToEndOfStream {
                present: available as u64,
                fin_seen,
            };
            Some((message, bytes.len()))
        }
    }
}

/// Read a chunked body: its bytes, how it ended, and how much of the stream it
/// consumed.
fn read_chunked(bytes: &[u8]) -> (Vec<u8>, BodyEnd, usize) {
    let mut body: Vec<u8> = Vec::new();
    // What the stream held, which is not what was kept once the ceiling
    // fires: the record must report the first and hold the second.
    let mut present = 0u64;
    let mut at = 0usize;
    loop {
        let Some((line, next)) = read_line(bytes, at) else {
            let present = present.max(body.len() as u64);
            return (body, BodyEnd::ChunkedTruncated { present }, bytes.len());
        };
        // The size line may carry chunk extensions after a semicolon.
        let size_text = line.split(|b| *b == b';').next().unwrap_or(&[]);
        let Ok(size) = u64::from_str_radix(lossy(trim(size_text)).trim(), 16) else {
            return (body, BodyEnd::ChunkedMalformed { at: at as u64 }, at);
        };
        at = next;
        if size == 0 {
            // The trailer fields, then the final blank line. They must be
            // consumed as part of this body: a `consumed` that stops at the
            // zero chunk leaves the reader inside the trailer, and every
            // later message on the connection is lost behind it.
            let mut trailer = at;
            let mut lines = 0usize;
            loop {
                match read_line(bytes, trailer) {
                    Some((b"", next)) => {
                        trailer = next;
                        break;
                    }
                    Some((line, next)) if lines < MAX_HEADERS && line.len() <= MAX_HEADER_LINE => {
                        trailer = next;
                        lines += 1;
                    }
                    // A trailer this build will not walk, or a stream that
                    // ends inside it: the body itself is complete either way,
                    // and nothing after it is claimed to be read.
                    _ => {
                        trailer = bytes.len();
                        break;
                    }
                }
            }
            return (body, BodyEnd::ChunkedComplete, trailer.min(bytes.len()));
        }
        let want = usize::try_from(size).unwrap_or(usize::MAX);
        let available = bytes.len().saturating_sub(at);
        if available < want {
            // The ceiling applies here as much as on the whole-chunk path:
            // this is the branch a chunk claiming two gigabytes takes.
            present = present.saturating_add(available as u64);
            let room = MAX_BODY_BYTES.saturating_sub(body.len());
            body.extend_from_slice(&bytes[at..at.saturating_add(room).min(bytes.len())]);
            return (body, BodyEnd::ChunkedTruncated { present }, bytes.len());
        }
        present = present.saturating_add(want as u64);
        if body.len() < MAX_BODY_BYTES {
            let room = MAX_BODY_BYTES - body.len();
            body.extend_from_slice(&bytes[at..at + want.min(room)]);
        }
        at = at.saturating_add(want);
        // The CRLF after the chunk data.
        at = at.saturating_add(2).min(bytes.len());
    }
}

/// Whether a response with this status, answering this method, may carry a
/// body at all (RFC 9112 §6.3 rules 1 and 2).
///
/// `answering` is the method of the request this answers, where the capture
/// holds it. Without it the method-based rule cannot be applied and only the
/// status-based one is.
fn can_carry_a_body(status: Option<u16>, answering: Option<&str>) -> bool {
    if answering.is_some_and(|method| method.eq_ignore_ascii_case("HEAD")) {
        return false;
    }
    // A 2xx answer to CONNECT has no body: what follows it is the TUNNEL, and
    // the tunnel is not this response's content. Framing it as one would hand
    // an examiner the proxied conversation's ciphertext as an HTTP body
    // artifact -- worse than not reading it, because it would be filed under a
    // content type and a URL that describe the request rather than the bytes.
    if answering.is_some_and(|method| method.eq_ignore_ascii_case("CONNECT"))
        && status.is_some_and(|status| (200..=299).contains(&status))
    {
        return false;
    }
    match status {
        // Informational, No Content and Not Modified carry none, whatever
        // their headers say. A `Content-Length` on a 304 describes the
        // representation that was NOT sent.
        Some(status) => !((100..=199).contains(&status) || status == 204 || status == 304),
        None => true,
    }
}

/// What a message declared its body's length to be.
enum Declared {
    Length(u64),
    None,
    /// More than one length, and they do not agree.
    Disagreement(String),
}

/// Read `Content-Length`, which may legally arrive as a list of identical
/// values and may hostilely arrive as a list of different ones (RFC 9110
/// §8.6). The header map has already joined repeats with `, `, so both forms
/// arrive here the same way.
fn content_length(value: Option<&str>) -> Declared {
    let Some(value) = value else {
        return Declared::None;
    };
    let mut lengths: Vec<u64> = Vec::new();
    for part in value.split(',') {
        match part.trim().parse::<u64>() {
            Ok(length) => lengths.push(length),
            // A value that is not a number at all is not a length, and the
            // message is as unframeable as one with two.
            Err(_) => return Declared::Disagreement(value.to_string()),
        }
    }
    match lengths.first().copied() {
        None => Declared::None,
        Some(first) if lengths.iter().all(|l| *l == first) => Declared::Length(first),
        Some(_) => Declared::Disagreement(value.to_string()),
    }
}

/// One line at `from`, without its terminator, and the offset after it.
/// `None` when no terminator is present: the stream ended mid-line.
fn read_line(bytes: &[u8], from: usize) -> Option<(&[u8], usize)> {
    let rest = bytes.get(from..)?;
    let position = rest.iter().position(|b| *b == b'\n')?;
    let end = if position > 0 && rest[position - 1] == b'\r' {
        position - 1
    } else {
        position
    };
    Some((&rest[..end], from + position + 1))
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|p| p + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

/// A header value as text. Lossy on purpose: a header is a byte string and a
/// non-UTF-8 byte in one is evidence, so it is rendered rather than dropped.
fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

/// How a response was matched to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pairing {
    /// The *n*th response answers the *n*th request, and both streams are
    /// contiguous, so that order is what the capture holds.
    InOrder,
    /// The same assumption over a stream with a gap in it: the missing bytes
    /// may have held a whole message, so the pairing may be wrong.
    InOrderOverAGap,
    /// The same assumption over a conversation whose start this capture does
    /// not hold. There is no gap to count — the bytes before the first one
    /// captured are missing and unmeasurable — and the *n*th response here
    /// may answer a request that was sent before the capture began.
    InOrderFromAnIncompleteStart,
    /// A request with no response in the capture.
    RequestUnanswered,
    /// A response with no request: the capture began mid-connection, or the
    /// request direction was not captured.
    ResponseUnmatched,
}

impl Pairing {
    pub fn as_str(&self) -> &'static str {
        match self {
            Pairing::InOrder => "in_order",
            Pairing::InOrderOverAGap => "in_order_over_a_gap",
            Pairing::InOrderFromAnIncompleteStart => "in_order_from_an_incomplete_start",
            Pairing::RequestUnanswered => "request_unanswered",
            Pairing::ResponseUnmatched => "response_unmatched",
        }
    }

    /// The sentence the record carries, because "paired" is an inference and an
    /// examiner reading a request beside a response must know on what basis.
    pub fn basis(&self) -> &'static str {
        match self {
            Pairing::InOrder => {
                "HTTP/1.1 answers requests on one connection in order, so the nth response \
                 answers the nth request. Both directions of this conversation were captured \
                 without a gap, so that order is what the capture holds."
            }
            Pairing::InOrderOverAGap => {
                "Paired by order, which is how HTTP/1.1 answers requests on one connection -- \
                 but one direction of this conversation has a gap in it, and the missing bytes \
                 may have held a whole message. THIS PAIRING MAY BE WRONG."
            }
            Pairing::InOrderFromAnIncompleteStart => {
                "Paired by order, which is how HTTP/1.1 answers requests on one connection -- \
                 but THIS CAPTURE DOES NOT HOLD THE START OF THE CONNECTION. No handshake was \
                 captured for it, so the first byte held is the first byte the capture saw and \
                 not the connection's first byte; what came before is missing and its size is \
                 not even knowable. The response beside this request may answer one sent before \
                 the capture began. THIS PAIRING MAY BE WRONG."
            }
            Pairing::RequestUnanswered => {
                "This request has no response in the capture: the answer was not captured, or \
                 none was sent."
            }
            Pairing::ResponseUnmatched => {
                "This response answers a request the capture does not hold: the capture began \
                 mid-connection, or the request direction was not captured."
            }
        }
    }
}

/// A request and the response that answered it, as far as the capture allows.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub request: Option<Message>,
    pub response: Option<Message>,
    pub pairing: Pairing,
}

/// What is wrong with the conversation a pairing is made over.
///
/// Both of these turn the ordering assumption from a statement about the
/// protocol into one that may be wrong, and they are different faults: a gap
/// has a measurable size, a missing start does not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Doubt {
    /// Either direction has a hole in it.
    pub gaps: bool,
    /// Either direction began mid-connection: no handshake was captured, so
    /// the bytes before the first one held are missing and unmeasurable.
    pub mid_connection: bool,
}

impl Doubt {
    /// The pairing a paired transaction gets, worst fault first.
    fn pairing(&self) -> Pairing {
        if self.gaps {
            Pairing::InOrderOverAGap
        } else if self.mid_connection {
            Pairing::InOrderFromAnIncompleteStart
        } else {
            Pairing::InOrder
        }
    }
}

/// Pair the messages of the two directions.
pub fn pair(requests: Vec<Message>, responses: Vec<Message>, doubt: Doubt) -> Vec<Transaction> {
    let mut out = Vec::new();
    let mut responses = responses.into_iter();
    for request in requests {
        match responses.next() {
            Some(response) => out.push(Transaction {
                request: Some(request),
                response: Some(response),
                pairing: doubt.pairing(),
            }),
            None => out.push(Transaction {
                request: Some(request),
                response: None,
                pairing: Pairing::RequestUnanswered,
            }),
        }
    }
    for response in responses {
        out.push(Transaction {
            request: None,
            response: Some(response),
            pairing: Pairing::ResponseUnmatched,
        });
    }
    out
}

/// Bytes of one *decoded* body held in memory and handed on as an artifact.
///
/// A content coding turns a small body into a large one, and a hostile one
/// into an unbounded one, so the inflated size has its own ceiling rather
/// than inheriting [`MAX_BODY_BYTES`], which bounds what crossed the wire.
pub const MAX_DECODED_BODY_BYTES: usize = 32 * 1024 * 1024;

/// What became of a body's content coding.
///
/// The stored bytes are the object wherever this build can produce it, because
/// an examiner asking "what did that server send down" means the page, not the
/// deflate stream. What was on the wire is named in every case, so the artifact
/// is never mistaken for the bytes that crossed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Coding {
    /// No `Content-Encoding`, or `identity`: the bytes are the object already.
    Identity,
    /// Decoded in full by this build.
    Decoded { encoding: String },
    /// Decoding stopped inside the stream. A body cut by a gap or by the end
    /// of the capture cannot inflate past where it stops; what did inflate is
    /// kept, because it is evidence.
    Truncated { encoding: String, detail: String },
    /// Decoding reached [`MAX_DECODED_BODY_BYTES`]. The only safe answer to a
    /// stream that claims to inflate forever.
    Capped { encoding: String },
    /// A coding this build does not decode. The wire bytes are kept:
    /// refusing to decode is not refusing to record.
    NotDecoded { encoding: String },
    /// The capture's whole body budget ([`MAX_BODY_BYTES_PER_CAPTURE`]) was
    /// spent by this body and every one before it. What fits is kept.
    CaptureBudgetExhausted { encoding: Option<String> },
}

impl Coding {
    /// Whether the stored bytes are the whole object.
    pub fn is_whole(&self) -> bool {
        matches!(self, Coding::Identity | Coding::Decoded { .. })
    }

    /// The vocabulary term for what the stored bytes fall short by, or `None`
    /// when they do not.
    pub fn reason(&self) -> Option<seance_core::io::IncompleteReason> {
        use seance_core::io::IncompleteReason as R;
        match self {
            Coding::Identity | Coding::Decoded { .. } => None,
            Coding::Truncated { .. } => Some(R::ShortRead),
            Coding::Capped { .. } | Coding::CaptureBudgetExhausted { .. } => Some(R::CapReached),
            Coding::NotDecoded { .. } => Some(R::Compressed),
        }
    }

    /// The coding named on the wire, where one was.
    pub fn encoding(&self) -> Option<&str> {
        match self {
            Coding::Identity => None,
            Coding::Decoded { encoding }
            | Coding::Truncated { encoding, .. }
            | Coding::Capped { encoding }
            | Coding::NotDecoded { encoding } => Some(encoding),
            Coding::CaptureBudgetExhausted { encoding } => encoding.as_deref(),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Coding::Identity => "identity",
            Coding::Decoded { .. } => "decoded",
            Coding::Truncated { .. } => "decode_truncated",
            Coding::Capped { .. } => "decode_capped",
            Coding::NotDecoded { .. } => "not_decoded",
            Coding::CaptureBudgetExhausted { .. } => "capture_budget_exhausted",
        }
    }

    /// The sentence the body artifact carries, because "this is the body" is
    /// not a safe thing to say without it.
    pub fn statement(&self) -> String {
        match self {
            Coding::Identity => {
                "The bytes are as they crossed the wire: the message declared no content \
                 coding."
                    .to_string()
            }
            Coding::Decoded { encoding } => format!(
                "These bytes are the decoded body. The message declared `Content-Encoding: \
                 {encoding}` and the stream decoded in full; `wire_bytes` is what crossed the \
                 wire."
            ),
            Coding::Truncated { encoding, detail } => format!(
                "These bytes are a PREFIX of the body. The message declared \
                 `Content-Encoding: {encoding}` and the {encoding} stream ended before it was \
                 complete ({detail}) -- the body was cut by a gap in the capture or by its \
                 end, so what inflated is kept and the rest is not recoverable from this \
                 capture."
            ),
            Coding::Capped { encoding } => format!(
                "These bytes are a PREFIX of the body: the {encoding} stream inflated past \
                 this build's ceiling of {MAX_DECODED_BODY_BYTES} bytes and was cut there."
            ),
            Coding::CaptureBudgetExhausted { encoding } => format!(
                "These bytes are a PREFIX of the body: this capture's whole budget for bodies \
                 ({MAX_BODY_BYTES_PER_CAPTURE} bytes across every message) was spent by this \
                 body and the ones before it, so it was cut where the budget ran out{}.",
                encoding
                    .as_deref()
                    .map(|e| format!(" (its content coding was `{e}`)"))
                    .unwrap_or_default()
            ),
            Coding::NotDecoded { encoding } => format!(
                "These bytes are as they crossed the wire, still encoded. The message \
                 declared `Content-Encoding: {encoding}`, which this build does not decode, so \
                 the object itself is NOT in this artifact."
            ),
        }
    }
}

/// A body's bytes as this build can best present them, and what was done.
#[derive(Debug, Clone)]
pub struct BodyBytes {
    pub bytes: Vec<u8>,
    pub coding: Coding,
    /// How many bytes the message's body occupied on the wire.
    pub wire_bytes: usize,
}

/// Bytes of decoded body one capture will hold across every message.
///
/// [`MAX_DECODED_BODY_BYTES`] bounds one body and is no bound on the run: ten
/// thousand transactions is the emission cap, and a capture of a few megabytes
/// can hold hundreds of small gzip streams that each inflate to the per-body
/// ceiling. This is the number that keeps the artifact set inside a working
/// set, and a body cut by it says which ceiling cut it.
pub const MAX_BODY_BYTES_PER_CAPTURE: u64 = 256 * 1024 * 1024;

/// The body of one message, decoded where this build can decode it, bounded
/// by what the capture has left to hold.
pub fn body_bytes_within(message: &Message, budget_remaining: u64) -> BodyBytes {
    let mut out = body_bytes(message);
    let remaining = usize::try_from(budget_remaining).unwrap_or(usize::MAX);
    if out.bytes.len() > remaining {
        out.bytes.truncate(remaining);
        out.coding = Coding::CaptureBudgetExhausted {
            encoding: out.coding.encoding().map(str::to_string),
        };
    }
    out
}

/// The body of one message, decoded where this build can decode it.
pub fn body_bytes(message: &Message) -> BodyBytes {
    let wire_bytes = message.body.len();
    let declared = message
        .header("content-encoding")
        .map(str::trim)
        .unwrap_or("");
    let lowered = declared.to_ascii_lowercase();
    let identity = lowered.is_empty() || lowered == "identity";
    if identity {
        return BodyBytes {
            bytes: message.body.clone(),
            coding: Coding::Identity,
            wire_bytes,
        };
    }
    let decoder: Option<Decoder> = match lowered.as_str() {
        "gzip" | "x-gzip" => Some(Decoder::Gzip),
        "deflate" => Some(Decoder::Deflate),
        _ => None,
    };
    let Some(decoder) = decoder else {
        return BodyBytes {
            bytes: message.body.clone(),
            coding: Coding::NotDecoded {
                encoding: declared.to_string(),
            },
            wire_bytes,
        };
    };
    let (bytes, stop) = inflate(decoder, &message.body);
    let coding = match stop {
        InflateStop::Complete => Coding::Decoded { encoding: lowered },
        InflateStop::Capped => Coding::Capped { encoding: lowered },
        InflateStop::Stopped { detail } => Coding::Truncated {
            encoding: lowered,
            detail,
        },
    };
    BodyBytes {
        bytes,
        coding,
        wire_bytes,
    }
}

/// Which decoder a named coding calls for.
#[derive(Debug, Clone, Copy)]
enum Decoder {
    Gzip,
    /// `deflate`, which is a zlib stream by the RFC and a raw deflate stream
    /// about as often in practice.
    Deflate,
}

enum InflateStop {
    Complete,
    Capped,
    Stopped { detail: String },
}

/// Inflate up to the ceiling, keeping whatever came out.
///
/// `read_to_end` on a truncated stream returns an error *and* leaves the bytes
/// it produced in the buffer, which is exactly what is wanted here: the prefix
/// of a page is evidence, and a body cut by a gap is the ordinary case on a
/// real capture rather than a corner one.
fn inflate(decoder: Decoder, wire: &[u8]) -> (Vec<u8>, InflateStop) {
    use std::io::Read;
    let mut out = Vec::new();
    // One byte over the ceiling distinguishes "exactly the ceiling" from
    // "more than this build will hold".
    let ceiling = MAX_DECODED_BODY_BYTES as u64 + 1;
    let result = match decoder {
        Decoder::Gzip => flate2::read::GzDecoder::new(wire)
            .take(ceiling)
            .read_to_end(&mut out),
        Decoder::Deflate => {
            let zlib = flate2::read::ZlibDecoder::new(wire)
                .take(ceiling)
                .read_to_end(&mut out);
            // A server that omits the zlib header is still understood, and
            // the raw attempt starts from an empty buffer so no bytes from
            // the failed one can be carried into it.
            if zlib.is_err() && out.is_empty() {
                flate2::read::DeflateDecoder::new(wire)
                    .take(ceiling)
                    .read_to_end(&mut out)
            } else {
                zlib
            }
        }
    };
    if out.len() > MAX_DECODED_BODY_BYTES {
        out.truncate(MAX_DECODED_BODY_BYTES);
        return (out, InflateStop::Capped);
    }
    match result {
        Ok(_) => (out, InflateStop::Complete),
        Err(error) => (
            out,
            InflateStop::Stopped {
                detail: error.to_string(),
            },
        ),
    }
}

/// Which direction of a conversation held the requests, decided by the bytes.
///
/// Not by who opened the connection: a capture that begins mid-conversation
/// has no handshake, and the flow's "initiator" is then whoever this capture
/// saw speak first — which is often the server. Not by port either, for the
/// reason this module does not sniff by port at all.
///
/// Where only the response direction is HTTP, the *other* direction is named
/// as the one that would have held the requests, so its responses are reported
/// as answering requests this capture does not hold rather than as
/// unexplained.
pub fn request_direction(out_prefix: &[u8], in_prefix: &[u8]) -> Option<crate::flows::Direction> {
    use crate::flows::Direction;
    match (sniff(out_prefix), sniff(in_prefix)) {
        (Some(Kind::Request), _) => Some(Direction::Out),
        (_, Some(Kind::Request)) => Some(Direction::In),
        (Some(Kind::Response), _) => Some(Direction::In),
        (_, Some(Kind::Response)) => Some(Direction::Out),
        (None, None) => None,
    }
}

/// Transactions one capture will hand up as records.
///
/// A capture of a scan holds tens of thousands of one-request connections;
/// past this the count is reported and the records are not written, which is
/// the difference between a bounded run and an unusable case.
pub const MAX_TRANSACTIONS_PER_CAPTURE: usize = 10_000;

/// What one direction of a conversation offered the parser, and what it could
/// not.
///
/// Every number here is about the *stream*, not about a message: an examiner
/// reading a transaction needs to know that the direction it came from has a
/// hole in it before reading the message beside it as complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFacts {
    /// Whether the reassembler held this direction at all. `false` means the
    /// capture holds no bytes this way — the direction was not captured, or
    /// carried none.
    pub present: bool,
    /// Bytes offered to the parser: the stream's contiguous prefix.
    pub parsed_bytes: u64,
    /// Bytes the stream holds *beyond* its first gap. They are in the capture
    /// and were not parsed, because a message read across a hole would be a
    /// message nobody sent.
    pub bytes_after_first_gap: u64,
    /// The gaps themselves, and what they total.
    pub gaps: usize,
    pub gap_bytes: u64,
    /// Bytes of the readable prefix no message consumed.
    pub trailing_unparsed: u64,
    /// Whether [`MAX_MESSAGES_PER_STREAM`] fired on this direction.
    pub message_cap_reached: bool,
    /// Messages parsed here that were the other kind — a response on the
    /// request side. Counted rather than paired, because pairing them would
    /// invent a conversation.
    pub messages_of_the_other_kind: usize,
    /// Whether this direction's close was captured.
    pub fin_seen: bool,
    /// Whether the stream's offset zero is the connection's first byte.
    /// `false` means the capture did not hold the handshake, so what came
    /// before the first byte held is missing and its size is not knowable —
    /// a different fault from a gap, and a worse one to read past.
    pub base_from_syn: bool,
    /// Places where two segments claimed the same offsets with DIFFERENT
    /// bytes. The first bytes are what was read and the others are in no
    /// record: that is the mechanism behind a family of sensor evasions, so a
    /// message read out of such a stream must never present as unqualified.
    pub conflicts: usize,
    pub conflict_bytes: u64,
    /// Why the reassembler stopped, and at what offset.
    pub stop: &'static str,
    pub stop_at: Option<u64>,
    /// Whether reading this direction stopped at a start line longer than
    /// [`MAX_HEADER_LINE`].
    pub start_line_too_long: bool,
    /// Whether this direction begins with HTTP/2's connection preface, which
    /// this build does not read.
    pub http2_preface: bool,
}

impl Default for StreamFacts {
    fn default() -> Self {
        StreamFacts {
            present: false,
            parsed_bytes: 0,
            bytes_after_first_gap: 0,
            gaps: 0,
            gap_bytes: 0,
            trailing_unparsed: 0,
            message_cap_reached: false,
            messages_of_the_other_kind: 0,
            fin_seen: false,
            // A direction the capture does not hold makes no claim about a
            // handshake either way; the `present` flag is what says whether
            // any of these numbers mean anything.
            base_from_syn: false,
            conflicts: 0,
            conflict_bytes: 0,
            stop: "not_captured",
            stop_at: None,
            start_line_too_long: false,
            http2_preface: false,
        }
    }
}

impl StreamFacts {
    /// The stream's own facts, with no parse to draw the message-level ones
    /// from. For a reader that is not HTTP: [`crate::tls`] needs every one of
    /// these and none of the message counts.
    pub fn of_stream(stream: Option<&crate::reassemble::Stream>) -> Self {
        StreamFacts::of(stream, None)
    }

    fn of(stream: Option<&crate::reassemble::Stream>, parsed: Option<&StreamMessages>) -> Self {
        let Some(stream) = stream else {
            return StreamFacts::default();
        };
        let holes = stream.holes();
        let prefix = stream.contiguous_prefix().len() as u64;
        use crate::reassemble::StreamStop;
        let (stop, stop_at) = match stream.stop {
            StreamStop::EndOfCapture => ("end_of_capture", None),
            StreamStop::ByteCeiling { at } => ("byte_ceiling", Some(at)),
            StreamStop::RunCeiling { at } => ("run_ceiling", Some(at)),
            StreamStop::TotalBudget { at } => ("total_budget", Some(at)),
        };
        StreamFacts {
            present: true,
            parsed_bytes: prefix,
            bytes_after_first_gap: stream.bytes_held().saturating_sub(prefix),
            gaps: holes.len(),
            gap_bytes: holes.iter().fold(0u64, |a, h| a.saturating_add(h.length)),
            trailing_unparsed: parsed.map_or(0, |p| p.trailing_unparsed),
            message_cap_reached: parsed.is_some_and(|p| p.message_cap_reached),
            messages_of_the_other_kind: 0,
            fin_seen: stream.fin_seen,
            base_from_syn: stream.base_from_syn,
            conflicts: stream.conflicts.len(),
            conflict_bytes: stream
                .conflicts
                .iter()
                .fold(0u64, |a, c| a.saturating_add(c.length)),
            stop,
            stop_at,
            start_line_too_long: parsed.is_some_and(|p| p.start_line_too_long),
            http2_preface: parsed.is_some_and(|p| p.http2_preface),
        }
    }

    /// Whether this direction was read end to end with nothing in doubt —
    /// including the start of it: a stream whose handshake the capture does
    /// not hold is missing everything before its first byte, and that is not
    /// a complete reading of a conversation however completely the bytes
    /// present parsed.
    pub fn is_complete(&self) -> bool {
        self.base_from_syn
            && self.gaps == 0
            && self.conflicts == 0
            && self.trailing_unparsed == 0
            && !self.message_cap_reached
            && self.messages_of_the_other_kind == 0
            && self.stop == "end_of_capture"
            && !self.start_line_too_long
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "present": self.present,
            "parsed_bytes": self.parsed_bytes,
            "bytes_after_first_gap": self.bytes_after_first_gap,
            "gaps": self.gaps,
            "gap_bytes": self.gap_bytes,
            "trailing_unparsed": self.trailing_unparsed,
            "message_cap_reached": self.message_cap_reached,
            "messages_of_the_other_kind": self.messages_of_the_other_kind,
            "fin_seen": self.fin_seen,
            "base_from_syn": self.base_from_syn,
            "conflicts": self.conflicts,
            "conflict_bytes": self.conflict_bytes,
            "stop": self.stop,
            "stop_at": self.stop_at,
            "start_line_too_long": self.start_line_too_long,
            "http2_preface": self.http2_preface,
            "complete": self.is_complete(),
        })
    }
}

/// One TCP conversation's HTTP/1.x, as far as the two reassembled streams
/// allow.
#[derive(Debug, Clone)]
pub struct Conversation {
    /// The conversation this came from, keyed the way the flow table keys it
    /// so a transaction and its flow cannot disagree about which one they
    /// describe.
    pub flow: crate::flows::FlowKey,
    /// The endpoint whose bytes parsed as requests, and the one that answered.
    /// Decided by [`request_direction`].
    pub client: crate::flows::Endpoint,
    pub server: crate::flows::Endpoint,
    /// Which direction of the flow the requests were on.
    pub requests_from: crate::flows::Direction,
    pub transactions: Vec<Transaction>,
    pub requests: StreamFacts,
    pub responses: StreamFacts,
}

impl Conversation {
    /// Whether either direction has a hole, which is what turns the ordering
    /// assumption from a statement about the protocol into one that may be
    /// wrong.
    pub fn over_a_gap(&self) -> bool {
        self.requests.gaps > 0 || self.responses.gaps > 0
    }

    /// Whether either direction began mid-connection.
    pub fn mid_connection(&self) -> bool {
        (self.requests.present && !self.requests.base_from_syn)
            || (self.responses.present && !self.responses.base_from_syn)
    }
}

/// Read every TCP conversation's HTTP, pairing each response to a request.
///
/// Both halves are needed: the streams hold the bytes and the flow table holds
/// which endpoint sent them, and a transaction labelled the other way round
/// would name the server as the client on every row an examiner reads.
pub fn conversations(
    flows: &crate::flows::FlowTable,
    streams: &[crate::reassemble::Stream],
) -> Vec<Conversation> {
    use crate::flows::{Direction, FlowKey};
    use crate::reassemble::{index_streams, stream_of};
    let mut out = Vec::new();
    // Indexed once: see `index_streams`.
    let index = index_streams(streams);
    for flow in flows.flows() {
        let key = FlowKey::new(flow.protocol, flow.initiator, flow.responder);
        let outbound = stream_of(&index, key, Direction::Out);
        let inbound = stream_of(&index, key, Direction::In);
        fn prefix(s: Option<&crate::reassemble::Stream>) -> &[u8] {
            s.map_or(&[][..], |s| s.contiguous_prefix())
        }
        // A conversation that is HTTP/2 is recognised even though it is not
        // read, so the capture can say HTTP/2 was present rather than saying
        // nothing at all about it.
        let http2 = prefix(outbound).starts_with(HTTP2_PREFACE)
            || prefix(inbound).starts_with(HTTP2_PREFACE);
        let Some(requests_from) = request_direction(prefix(outbound), prefix(inbound)) else {
            if http2 {
                out.push(Conversation {
                    flow: key,
                    client: flow.initiator,
                    server: flow.responder,
                    requests_from: Direction::Out,
                    transactions: Vec::new(),
                    requests: StreamFacts {
                        http2_preface: prefix(outbound).starts_with(HTTP2_PREFACE),
                        ..StreamFacts::of_stream(outbound)
                    },
                    responses: StreamFacts {
                        http2_preface: prefix(inbound).starts_with(HTTP2_PREFACE),
                        ..StreamFacts::of_stream(inbound)
                    },
                });
            }
            continue;
        };
        let (request_stream, response_stream) = match requests_from {
            Direction::Out => (outbound, inbound),
            Direction::In => (inbound, outbound),
        };
        // Direction::Out is initiator to responder, so the client is the
        // initiator only when the requests are on that side.
        let (client, server) = match requests_from {
            Direction::Out => (flow.initiator, flow.responder),
            Direction::In => (flow.responder, flow.initiator),
        };

        // The requests first: the methods they used decide how the responses
        // beside them are framed, because a response to HEAD carries no body
        // however long it says its representation is.
        let parsed_requests =
            request_stream.map(|s| parse_stream(s.contiguous_prefix(), s.fin_seen));
        let methods: Vec<&str> = parsed_requests
            .as_ref()
            .map(|p| {
                p.messages
                    .iter()
                    .filter(|m| m.kind == Kind::Request)
                    .map(|m| m.method.as_deref().unwrap_or(""))
                    .collect()
            })
            .unwrap_or_default();
        let parsed_responses = response_stream
            .map(|s| parse_stream_with_methods(s.contiguous_prefix(), s.fin_seen, &methods));
        let mut requests = StreamFacts::of(request_stream, parsed_requests.as_ref());
        let mut responses = StreamFacts::of(response_stream, parsed_responses.as_ref());

        let split = |parsed: Option<StreamMessages>, want: Kind| -> (Vec<Message>, usize) {
            let Some(parsed) = parsed else {
                return (Vec::new(), 0);
            };
            let total = parsed.messages.len();
            let kept: Vec<Message> = parsed
                .messages
                .into_iter()
                .filter(|m| m.kind == want)
                .collect();
            let other = total - kept.len();
            (kept, other)
        };
        let (request_messages, request_other) = split(parsed_requests, Kind::Request);
        let (response_messages, response_other) = split(parsed_responses, Kind::Response);
        requests.messages_of_the_other_kind = request_other;
        responses.messages_of_the_other_kind = response_other;

        let doubt = Doubt {
            gaps: requests.gaps > 0 || responses.gaps > 0,
            // A direction the capture holds without its handshake began
            // mid-connection. A direction it does not hold at all says
            // nothing either way, and is not counted as one.
            mid_connection: (requests.present && !requests.base_from_syn)
                || (responses.present && !responses.base_from_syn),
        };
        let transactions = pair(request_messages, response_messages, doubt);
        // A conversation with no transaction is kept only where there is
        // something to say about it: that it was HTTP/2 and was not read.
        if transactions.is_empty() && !(requests.http2_preface || responses.http2_preface) {
            continue;
        }
        out.push(Conversation {
            flow: key,
            client,
            server,
            requests_from,
            transactions,
            requests,
            responses,
        });
    }
    out
}

/// Fields read from one form. A login form has three; a crafted body can
/// claim thousands.
pub const MAX_FORM_FIELDS: usize = 256;

/// Bytes of one field's value kept on the record. The whole body is handed on
/// as its own artifact, so this bounds the *record*, not the evidence.
pub const MAX_FORM_VALUE_BYTES: usize = 4 * 1024;

/// The fields of a form, decoded.
///
/// This is where the answer to "what did they send" lives: a webmail message,
/// a login, a search. The body itself is handed on as an artifact whatever
/// happens here, so nothing depends on this decoding being complete — and
/// where it is not, it says so.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Form {
    /// Field name to value, percent-decoded, with a repeated name's values
    /// joined by `, ` — dropping one would lose evidence.
    pub fields: std::collections::BTreeMap<String, String>,
    /// Fields past [`MAX_FORM_FIELDS`], counted and not kept.
    pub fields_beyond_cap: usize,
    /// Values cut at [`MAX_FORM_VALUE_BYTES`]. The whole value is in the body
    /// artifact.
    pub values_truncated: usize,
    /// Pairs with no `=` at all, which is not a field and is not invented into
    /// one.
    pub malformed_pairs: usize,
}

impl Form {
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.fields_beyond_cap == 0 && self.malformed_pairs == 0
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "fields": self.fields.iter().map(|(k, v)| (k.clone(), serde_json::json!(v)))
                .collect::<serde_json::Map<_, _>>(),
            "field_count": self.fields.len(),
            "fields_beyond_cap": self.fields_beyond_cap,
            "values_truncated": self.values_truncated,
            "malformed_pairs": self.malformed_pairs,
        })
    }
}

/// Whether a content type is a URL-encoded form, ignoring its parameters —
/// `application/x-www-form-urlencoded; charset=UTF-8` is one.
pub fn is_urlencoded_form(content_type: Option<&str>) -> bool {
    content_type
        .map(|t| t.split(';').next().unwrap_or(t).trim().to_ascii_lowercase())
        .is_some_and(|t| t == "application/x-www-form-urlencoded")
}

/// The fields of a message's body, where the message says it is a URL-encoded
/// form. `None` where it says it is anything else: decoding a body against a
/// type it did not claim would invent fields.
pub fn form_fields(message: &Message) -> Option<Form> {
    if message.kind != Kind::Request || !is_urlencoded_form(message.content_type()) {
        return None;
    }
    Some(decode_pairs(&message.body))
}

/// The fields of a request target's query string, where it has one.
///
/// A GET form puts its answers here, and so does most tracking: the query is
/// as much "what was sent" as a body is.
pub fn query_fields(target: &str) -> Option<Form> {
    let (_, query) = target.split_once('?')?;
    // A fragment is not sent to the server, but a target that carries one is
    // what it is and the query stops there.
    let query = query.split('#').next().unwrap_or(query);
    if query.is_empty() {
        return None;
    }
    Some(decode_pairs(query.as_bytes()))
}

/// `a=1&b=two+words&c=%2F` as its fields.
fn decode_pairs(bytes: &[u8]) -> Form {
    let mut out = Form::default();
    for pair in bytes.split(|b| *b == b'&') {
        if pair.is_empty() {
            continue;
        }
        let Some(equals) = pair.iter().position(|b| *b == b'=') else {
            // A bare token is not a name with an empty value and not a value
            // with no name; it is counted and not guessed at.
            out.malformed_pairs += 1;
            continue;
        };
        if out.fields.len() >= MAX_FORM_FIELDS {
            out.fields_beyond_cap += 1;
            continue;
        }
        // The name is bounded like the value: a crafted body can make one
        // field name the size of the whole body, and it becomes a map key, a
        // JSON key and a copy of itself on the record.
        let mut name = percent_decode(&pair[..equals]);
        if cut_to(&mut name, MAX_FORM_VALUE_BYTES) {
            out.values_truncated += 1;
        }
        let mut value = percent_decode(&pair[equals + 1..]);
        if cut_to(&mut value, MAX_FORM_VALUE_BYTES) {
            out.values_truncated += 1;
        }
        let mut truncated_join = false;
        out.fields
            .entry(name)
            .and_modify(|held| {
                // A repeated name grows one value, so the field count bounds
                // nothing: the joined value has the same ceiling a single one
                // has.
                if held.len() >= MAX_FORM_VALUE_BYTES {
                    truncated_join = true;
                    return;
                }
                held.push_str(", ");
                held.push_str(&value);
                if cut_to(held, MAX_FORM_VALUE_BYTES) {
                    truncated_join = true;
                }
            })
            .or_insert(value);
        if truncated_join {
            out.values_truncated += 1;
        }
    }
    out
}

/// Cut a string to `max` bytes on a character boundary, so the record holds
/// text rather than half a code point. `true` where it cut.
fn cut_to(text: &mut String, max: usize) -> bool {
    if text.len() <= max {
        return false;
    }
    let mut cut = max;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    true
}

/// One form-encoded token: `%XX` is a byte, `+` is a space, everything else is
/// itself. Lossy at the end, because a value with a byte that is not valid
/// UTF-8 is evidence and rendering it beats dropping the field.
fn percent_decode(bytes: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' => {
                let digits = bytes.get(index + 1..index + 3).and_then(|d| {
                    let text = std::str::from_utf8(d).ok()?;
                    u8::from_str_radix(text, 16).ok()
                });
                match digits {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    // A `%` that is not an escape is a literal `%`: it is in
                    // the bytes, and dropping it would change the value.
                    None => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}
