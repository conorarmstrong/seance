//! HTTP over a stream: what is read, what is refused, and the three ways a
//! message can be a prefix of one.

use super::http::*;

/// A request as it is on the wire. Built from parts rather than written as one
/// literal: a wrapped literal keeps the leading spaces of each continuation
/// line, which would make every header name here start with whitespace — a
/// fixture that is not what any client sends.
fn request() -> Vec<u8> {
    req(
        &[
            "GET /login.php?u=admin HTTP/1.1",
            "Host: 203.78.103.109",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept: */*",
        ],
        b"",
    )
}

fn req(lines: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

// ── What is and is not HTTP ─────────────────────────────────────────────────

/// **Recognised by its own bytes, on any port.** A start line this does not
/// recognise is not HTTP, because any token matches the first word of a great
/// deal of binary traffic.
#[test]
fn a_message_is_recognised_by_its_start_line_and_nothing_else() {
    assert_eq!(sniff(b"GET / HTTP/1.1\r\n"), Some(Kind::Request));
    assert_eq!(sniff(b"POST /a HTTP/1.0\r\n"), Some(Kind::Request));
    assert_eq!(sniff(b"HTTP/1.1 200 OK\r\n"), Some(Kind::Response));
    // Not HTTP: a method with no version on the line, an unknown method, TLS,
    // and a bare token.
    assert_eq!(sniff(b"GET /only-a-path\r\n"), None);
    assert_eq!(sniff(b"FOO / HTTP/1.1\r\n"), None);
    assert_eq!(sniff(&[0x16, 0x03, 0x01, 0x02, 0x00]), None);
    assert_eq!(sniff(b"GETTING ON WITH IT"), None);
    assert_eq!(sniff(b""), None);
    // HTTP/2's preface is not HTTP/1 and is not claimed as one.
    assert_eq!(sniff(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), None);
}

// ── A whole request ─────────────────────────────────────────────────────────

#[test]
fn a_request_is_read_with_its_target_and_headers() {
    let out = parse_stream(&request(), false);
    assert_eq!(out.messages.len(), 1);
    let m = &out.messages[0];
    assert_eq!(m.kind, Kind::Request);
    assert_eq!(m.method.as_deref(), Some("GET"));
    // The target is what was sent, query string and all: an examiner
    // correlating a log needs the bytes, not a cleaned-up path.
    assert_eq!(m.target.as_deref(), Some("/login.php?u=admin"));
    assert_eq!(m.version.as_deref(), Some("HTTP/1.1"));
    assert_eq!(m.header("host"), Some("203.78.103.109"));
    assert_eq!(
        m.header("user-agent"),
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    );
    assert!(m.headers_complete);
    assert_eq!(m.body_end, BodyEnd::None);
    assert!(m.is_whole());
    let json = m.to_json();
    assert_eq!(json["method"], "GET");
    assert_eq!(json["complete"], serde_json::json!(true));
}

#[test]
fn header_names_are_case_insensitive_and_a_repeated_one_keeps_both_values() {
    let bytes = req(
        &[
            "GET / HTTP/1.1",
            "HOST: example.com",
            "Set-Cookie: a=1",
            "set-cookie: b=2",
        ],
        b"",
    );
    let out = parse_stream(&bytes, false);
    let m = &out.messages[0];
    assert_eq!(m.header("host"), Some("example.com"));
    assert_eq!(
        m.header("set-cookie"),
        Some("a=1, b=2"),
        "dropping one loses evidence, and which the server used is not knowable here"
    );
}

// ── The three ways a message is a prefix ────────────────────────────────────

/// **Headers cut by the end of the readable prefix**: what was read is
/// reported, and the message says its headers are not all of them.
#[test]
fn a_message_whose_headers_are_cut_says_so() {
    let bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: cu";
    let out = parse_stream(bytes, false);
    assert_eq!(out.messages.len(), 1);
    let m = &out.messages[0];
    assert!(!m.headers_complete);
    assert_eq!(m.header("host"), Some("example.com"));
    assert!(
        m.header("user-agent").is_none(),
        "a header line with no terminator is not a header"
    );
    assert!(!m.is_whole());
    assert_eq!(m.to_json()["headers_complete"], serde_json::json!(false));
}

/// **A body shorter than `Content-Length`**: both numbers are reported, and
/// the body is not called whole.
#[test]
fn a_body_shorter_than_its_declared_length_reports_both_numbers() {
    let mut bytes = req(
        &["POST /upload HTTP/1.1", "Host: h", "Content-Length: 100"],
        b"only twelve",
    );
    bytes.truncate(bytes.len());
    let out = parse_stream(&bytes, false);
    let m = &out.messages[0];
    assert_eq!(
        m.body_end,
        BodyEnd::LengthShort {
            declared: 100,
            present: 11
        }
    );
    assert_eq!(m.body, b"only twelve");
    assert!(!m.is_whole());
    assert_eq!(m.to_json()["body_end"], "length_short");
}

/// A body that satisfies its declared length is whole, and the bytes after it
/// belong to the next message rather than to this body.
#[test]
fn a_body_of_its_declared_length_is_whole_and_stops_there() {
    let mut bytes = req(
        &["POST /a HTTP/1.1", "Host: h", "Content-Length: 5"],
        b"12345",
    );
    bytes.extend_from_slice(&req(&["GET /b HTTP/1.1", "Host: h"], b""));
    let out = parse_stream(&bytes, false);
    assert_eq!(out.messages.len(), 2, "keep-alive carries both");
    assert_eq!(out.messages[0].body, b"12345");
    assert_eq!(
        out.messages[0].body_end,
        BodyEnd::LengthSatisfied { declared: 5 }
    );
    assert_eq!(out.messages[1].target.as_deref(), Some("/b"));
    assert!(
        out.messages[1].offset > 0,
        "the second message knows where it began"
    );
    assert_eq!(out.trailing_unparsed, 0);
}

/// **A response with no framing runs to the end of the stream**, and whether
/// that is the whole body depends on the FIN — which is a fact about the
/// capture, not about the message.
#[test]
fn a_response_with_no_framing_is_whole_only_if_the_connection_closed() {
    let bytes = {
        let mut b = Vec::new();
        b.extend_from_slice(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n");
        b.extend_from_slice(b"<html>hello</html>");
        b
    };
    let without_fin = parse_stream(&bytes, false);
    let m = &without_fin.messages[0];
    assert_eq!(m.status, Some(200));
    assert_eq!(m.reason.as_deref(), Some("OK"));
    assert_eq!(m.body, b"<html>hello</html>");
    assert_eq!(
        m.body_end,
        BodyEnd::ToEndOfStream {
            present: 18,
            fin_seen: false
        }
    );
    assert!(!m.is_whole(), "without a FIN the body may be a prefix");

    let with_fin = parse_stream(&bytes, true);
    assert!(
        with_fin.messages[0].is_whole(),
        "the connection closed, so the body ended where the stream did"
    );
}

// ── Chunked bodies ──────────────────────────────────────────────────────────

#[test]
fn a_chunked_body_is_assembled_and_its_terminator_makes_it_whole() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\n",
    );
    bytes.extend_from_slice(b"5\r\nhello\r\n");
    bytes.extend_from_slice(b"6\r\n world\r\n");
    bytes.extend_from_slice(b"0\r\n\r\n");

    let out = parse_stream(&bytes, false);
    let m = &out.messages[0];
    assert_eq!(m.body, b"hello world");
    assert_eq!(m.body_end, BodyEnd::ChunkedComplete);
    assert_eq!(m.content_type(), Some("text/html"));
    assert!(m.is_whole());
}

#[test]
fn a_chunked_body_the_stream_ended_inside_is_not_whole() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    bytes.extend_from_slice(b"5\r\nhello\r\n");
    bytes.extend_from_slice(b"20\r\nonly some of the twenty-t");

    let out = parse_stream(&bytes, false);
    let m = &out.messages[0];
    assert!(
        matches!(m.body_end, BodyEnd::ChunkedTruncated { .. }),
        "{:?}",
        m.body_end
    );
    assert!(m.body.starts_with(b"hello"), "what was read is kept");
    assert!(!m.is_whole());
}

#[test]
fn a_chunk_size_that_is_not_a_number_is_named_and_not_guessed() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    bytes.extend_from_slice(b"not-a-size\r\nbytes");

    let out = parse_stream(&bytes, false);
    let m = &out.messages[0];
    assert!(
        matches!(m.body_end, BodyEnd::ChunkedMalformed { .. }),
        "{:?}",
        m.body_end
    );
    assert!(m.body.is_empty());
    assert!(!m.is_whole());
}

#[test]
fn a_chunk_extension_after_a_semicolon_does_not_break_the_size() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    bytes.extend_from_slice(b"5;comment=here\r\nhello\r\n0\r\n\r\n");
    let out = parse_stream(&bytes, false);
    assert_eq!(out.messages[0].body, b"hello");
    assert_eq!(out.messages[0].body_end, BodyEnd::ChunkedComplete);
}

// ── Pairing ─────────────────────────────────────────────────────────────────

#[test]
fn requests_and_responses_pair_in_order_and_the_basis_is_on_the_record() {
    let requests = parse_stream(
        &{
            let mut b = req(&["GET /one HTTP/1.1", "Host: h"], b"");
            b.extend_from_slice(&req(&["GET /two HTTP/1.1", "Host: h"], b""));
            b
        },
        false,
    )
    .messages;
    let responses = parse_stream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        false,
    )
    .messages;
    assert_eq!(requests.len(), 2);
    assert_eq!(responses.len(), 2);

    let paired = pair(requests.clone(), responses.clone(), Doubt::default());
    assert_eq!(paired.len(), 2);
    assert_eq!(
        paired[0].request.as_ref().unwrap().target.as_deref(),
        Some("/one")
    );
    assert_eq!(paired[0].response.as_ref().unwrap().status, Some(200));
    assert_eq!(paired[1].response.as_ref().unwrap().status, Some(404));
    assert_eq!(paired[0].pairing, Pairing::InOrder);
    assert!(paired[0].pairing.basis().contains("in order"));

    // **Over a gap the same pairing may be wrong, and says so.**
    let over_a_gap = pair(
        requests.clone(),
        responses.clone(),
        Doubt {
            gaps: true,
            mid_connection: false,
        },
    );
    assert_eq!(over_a_gap[0].pairing, Pairing::InOrderOverAGap);
    assert!(over_a_gap[0]
        .pairing
        .basis()
        .contains("THIS PAIRING MAY BE WRONG"));
}

#[test]
fn a_request_with_no_response_and_a_response_with_no_request_each_say_which() {
    let requests = parse_stream(&req(&["GET /one HTTP/1.1", "Host: h"], b""), false).messages;
    let unanswered = pair(requests, Vec::new(), Doubt::default());
    assert_eq!(unanswered[0].pairing, Pairing::RequestUnanswered);
    assert!(unanswered[0].pairing.basis().contains("no response"));

    let responses = parse_stream(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false).messages;
    let unmatched = pair(Vec::new(), responses, Doubt::default());
    assert_eq!(unmatched[0].pairing, Pairing::ResponseUnmatched);
    assert!(unmatched[0]
        .pairing
        .basis()
        .contains("capture does not hold"));
}

// ── Ceilings, and bytes that are not HTTP ───────────────────────────────────

#[test]
fn bytes_after_a_message_that_are_not_http_are_counted_and_not_parsed() {
    let mut bytes = req(&["GET / HTTP/1.1", "Host: h"], b"");
    bytes.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef]);
    let out = parse_stream(&bytes, false);
    assert_eq!(out.messages.len(), 1);
    assert_eq!(out.trailing_unparsed, 9);
}

#[test]
fn a_header_block_beyond_the_ceiling_is_counted_rather_than_parsed() {
    let mut lines = vec!["GET / HTTP/1.1".to_string(), "Host: h".to_string()];
    for i in 0..(MAX_HEADERS + 10) {
        lines.push(format!("X-Pad-{i}: x"));
    }
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let bytes = req(&refs, b"");
    let out = parse_stream(&bytes, false);
    let m = &out.messages[0];
    assert_eq!(m.headers.len(), MAX_HEADERS);
    assert!(m.headers_dropped >= 10, "{}", m.headers_dropped);
    assert!(
        !m.is_whole(),
        "a message whose headers were not all read is not a message that was read"
    );
}

#[test]
fn a_header_line_with_no_colon_is_counted_and_not_invented() {
    let bytes = req(&["GET / HTTP/1.1", "Host: h", "this-is-not-a-header"], b"");
    let out = parse_stream(&bytes, false);
    let m = &out.messages[0];
    assert_eq!(m.headers_dropped, 1);
    assert_eq!(m.headers.len(), 1);
}

/// A stream that is not HTTP at all yields no message and no complaint: the
/// module is not the judge of what a stream should have been.
#[test]
fn a_stream_that_is_not_http_yields_nothing() {
    let out = parse_stream(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01], false);
    assert!(out.messages.is_empty());
    assert_eq!(out.trailing_unparsed, 6);
}

// ── Which direction sent the requests ───────────────────────────────────────

/// **The bytes decide, not who opened the connection.** A capture that begins
/// mid-conversation has no SYN to tell it who the client was, and a flow's
/// initiator is whoever this capture saw speak first — which on a
/// mid-connection capture is often the server.
#[test]
fn the_direction_that_sent_requests_is_decided_by_the_bytes() {
    use crate::flows::Direction;

    // The ordinary case: the initiator asked.
    assert_eq!(
        request_direction(b"GET / HTTP/1.1\r\n", b"HTTP/1.1 200 OK\r\n"),
        Some(Direction::Out)
    );
    // Reversed: the capture saw the server's bytes first, so the flow's
    // initiator is the server and the requests are on the other side.
    assert_eq!(
        request_direction(b"HTTP/1.1 200 OK\r\n", b"GET / HTTP/1.1\r\n"),
        Some(Direction::In)
    );
    // Only the response direction was captured. There are no request bytes,
    // and the direction that would have held them is still named, so the
    // responses are reported as answering requests the capture does not hold.
    assert_eq!(
        request_direction(b"HTTP/1.1 304 Not Modified\r\n", b""),
        Some(Direction::In)
    );
    assert_eq!(
        request_direction(b"", b"HTTP/1.1 200 OK\r\n"),
        Some(Direction::Out)
    );
    // Neither side is HTTP: nothing here is claimed.
    assert_eq!(request_direction(b"", b""), None);
    assert_eq!(
        request_direction(&[0x16, 0x03, 0x01, 0x02, 0x00], &[0x16, 0x03, 0x03]),
        None
    );
}

// ── The body as an object, not as a blob ────────────────────────────────────

/// **A gzip body is stored inflated**, because the object an examiner wants is
/// the page or the executable, not the coding. What was on the wire is still
/// stated, so the artifact is never mistaken for the bytes that crossed it.
#[test]
fn a_gzip_body_is_stored_decoded_and_says_what_was_on_the_wire() {
    let payload = b"<html>the page an examiner wants to read</html>";
    let wire = gzip(payload);
    let m = response_with_body(&[("Content-Encoding", "gzip")], &wire);
    let out = body_bytes(&m);
    assert_eq!(out.bytes, payload);
    assert_eq!(out.wire_bytes, wire.len());
    assert_eq!(
        out.coding,
        Coding::Decoded {
            encoding: "gzip".into()
        }
    );
    assert!(out.coding.is_whole());
}

/// A body with no coding is the object already, and is not touched.
#[test]
fn a_body_with_no_coding_is_stored_as_it_is() {
    let m = response_with_body(&[], b"plain bytes");
    let out = body_bytes(&m);
    assert_eq!(out.bytes, b"plain bytes");
    assert_eq!(out.coding, Coding::Identity);
    assert!(out.coding.is_whole());
    // `identity` is the same statement spelled out.
    let named = response_with_body(&[("Content-Encoding", "identity")], b"plain bytes");
    assert_eq!(body_bytes(&named).coding, Coding::Identity);
}

/// **A truncated gzip stream keeps what inflated and refuses to call it
/// whole.** A body cut by a gap or by the end of the capture cannot inflate
/// past where it stops, and the bytes that did inflate are evidence.
#[test]
fn a_truncated_gzip_body_keeps_what_inflated_and_is_not_called_whole() {
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let mut wire = gzip(&payload);
    wire.truncate(wire.len() / 2);
    let m = response_with_body(&[("Content-Encoding", "gzip")], &wire);
    let out = body_bytes(&m);
    assert!(
        !out.bytes.is_empty() && out.bytes.len() < payload.len(),
        "a prefix inflated, not nothing and not all of it: {} bytes",
        out.bytes.len()
    );
    assert!(
        payload.starts_with(&out.bytes),
        "and it is the object's prefix"
    );
    match &out.coding {
        Coding::Truncated { encoding, .. } => assert_eq!(encoding, "gzip"),
        other => panic!("{other:?}"),
    }
    assert!(!out.coding.is_whole());
}

/// **A coding this build does not decode is named, and the wire bytes are
/// kept.** Refusing to decode is not refusing to record.
#[test]
fn a_coding_this_build_cannot_decode_is_named_and_the_wire_bytes_are_kept() {
    for encoding in ["br", "zstd", "compress", "gzip, br"] {
        let m = response_with_body(&[("Content-Encoding", encoding)], b"\x00\x01\x02opaque");
        let out = body_bytes(&m);
        assert_eq!(out.bytes, b"\x00\x01\x02opaque", "{encoding}");
        assert_eq!(
            out.coding,
            Coding::NotDecoded {
                encoding: encoding.into()
            },
            "{encoding}"
        );
        assert!(!out.coding.is_whole(), "{encoding}");
        assert_eq!(
            out.coding.reason(),
            Some(seance_core::io::IncompleteReason::Compressed)
        );
    }
}

/// A body that inflates past this build's ceiling is cut there and says so,
/// which is the only safe answer to a stream that claims to inflate forever.
#[test]
fn a_body_that_inflates_past_the_ceiling_says_so() {
    let payload = vec![b'A'; MAX_DECODED_BODY_BYTES + 4096];
    let m = response_with_body(&[("Content-Encoding", "gzip")], &gzip(&payload));
    let out = body_bytes(&m);
    assert_eq!(out.bytes.len(), MAX_DECODED_BODY_BYTES);
    assert_eq!(
        out.coding,
        Coding::Capped {
            encoding: "gzip".into()
        }
    );
    assert!(!out.coding.is_whole());
    assert_eq!(
        out.coding.reason(),
        Some(seance_core::io::IncompleteReason::CapReached)
    );
}

/// `Content-Encoding` is a header name like any other: case does not change
/// what it says, and `x-gzip` is the same coding under an older name.
#[test]
fn the_coding_header_is_read_case_insensitively_and_under_its_old_name() {
    let payload = b"body";
    let m = response_with_body(&[("content-encoding", "GZIP")], &gzip(payload));
    assert_eq!(body_bytes(&m).bytes, payload);
    let m = response_with_body(&[("Content-Encoding", "x-gzip")], &gzip(payload));
    assert_eq!(body_bytes(&m).bytes, payload);
}

/// Servers send raw deflate under the name `deflate` about as often as they
/// send the zlib wrapper the RFC asks for, so both are read.
#[test]
fn deflate_is_read_with_or_without_its_zlib_wrapper() {
    let payload = b"deflated bytes";
    let m = response_with_body(&[("Content-Encoding", "deflate")], &zlib(payload));
    assert_eq!(body_bytes(&m).bytes, payload);
    let m = response_with_body(&[("Content-Encoding", "deflate")], &raw_deflate(payload));
    assert_eq!(
        body_bytes(&m).bytes,
        payload,
        "a server that omits the zlib header is still understood"
    );
}

// ── Fixtures for the body cases ─────────────────────────────────────────────

fn response_with_body(headers: &[(&str, &str)], body: &[u8]) -> Message {
    let mut lines = vec!["HTTP/1.1 200 OK".to_string(), "Server: nginx".to_string()];
    for (name, value) in headers {
        lines.push(format!("{name}: {value}"));
    }
    lines.push(format!("Content-Length: {}", body.len()));
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let bytes = req(&refs, body);
    let out = parse_stream(&bytes, true);
    assert_eq!(out.messages.len(), 1, "one message in the fixture");
    out.messages.into_iter().next().expect("the message")
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(bytes).expect("gzip");
    e.finish().expect("gzip")
}

fn zlib(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(bytes).expect("zlib");
    e.finish().expect("zlib")
}

fn raw_deflate(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(bytes).expect("deflate");
    e.finish().expect("deflate")
}

// ── Forms: what was actually sent ───────────────────────────────────────────

/// **The fields of a posted form are the answer to "what did they send".** A
/// webmail message, a login, a search: percent-decoded, `+` as a space, and a
/// repeated name keeping both values.
#[test]
fn a_posted_form_is_decoded_into_its_fields() {
    let body = b"to=lilytuckrige%40yahoo.com&from=me%2Bwork%40example.net&\
                 message=Stop+teaching+that+class%21&tag=a&tag=b";
    let bytes = req(
        &[
            "POST /secure/submit HTTP/1.1",
            "Host: www.willselfdestruct.com",
            "Content-Type: application/x-www-form-urlencoded",
            &format!("Content-Length: {}", body.len()),
        ],
        body,
    );
    let message = &parse_stream(&bytes, true).messages[0];
    let form = form_fields(message).expect("a form");
    assert_eq!(
        form.fields.get("to").map(String::as_str),
        Some("lilytuckrige@yahoo.com")
    );
    assert_eq!(
        form.fields.get("from").map(String::as_str),
        Some("me+work@example.net"),
        "%2B is a plus; a bare + is a space"
    );
    assert_eq!(
        form.fields.get("message").map(String::as_str),
        Some("Stop teaching that class!")
    );
    assert_eq!(
        form.fields.get("tag").map(String::as_str),
        Some("a, b"),
        "both values, because dropping one loses evidence"
    );
    assert_eq!(form.malformed_pairs, 0);
    assert_eq!(form.to_json()["field_count"], 4);
}

/// A body the message did not call a form is not decoded as one: fields read
/// out of JSON or a JPEG by splitting on `&` would be invented.
#[test]
fn a_body_that_is_not_a_form_is_not_decoded_as_one() {
    let body = b"{\"to\":\"a@b.c\"}";
    let bytes = req(
        &[
            "POST /api HTTP/1.1",
            "Host: h",
            "Content-Type: application/json",
            &format!("Content-Length: {}", body.len()),
        ],
        body,
    );
    let message = &parse_stream(&bytes, true).messages[0];
    assert!(form_fields(message).is_none());
    // The type's parameters do not change what it is.
    let bytes = req(
        &[
            "POST /login HTTP/1.1",
            "Host: h",
            "Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
            "Content-Length: 13",
        ],
        b"user=a&pass=b",
    );
    let message = &parse_stream(&bytes, true).messages[0];
    assert_eq!(form_fields(message).expect("a form").fields.len(), 2);
}

/// **A GET form puts its answers in the query string**, and so does most
/// tracking; the query is as much "what was sent" as a body is.
#[test]
fn the_query_string_of_a_target_is_decoded_too() {
    let form = query_fields("/search?q=how+to+wipe+a+laptop&sid=abc%3D%3D").expect("a query");
    assert_eq!(
        form.fields.get("q").map(String::as_str),
        Some("how to wipe a laptop")
    );
    assert_eq!(form.fields.get("sid").map(String::as_str), Some("abc=="));
    assert!(query_fields("/plain").is_none());
    assert!(query_fields("/plain?").is_none());
    // A fragment is not sent to a server; a target carrying one stops there.
    assert_eq!(
        query_fields("/a?x=1#frag")
            .expect("a query")
            .fields
            .get("x"),
        Some(&"1".to_string())
    );
}

/// A pair with no `=` is neither a name nor a value and is counted rather than
/// guessed at; a `%` that is not an escape is a literal `%`.
#[test]
fn a_pair_with_no_equals_is_counted_and_a_stray_percent_is_kept() {
    let form = query_fields("/a?justatoken&b=100%&c=%zz&d=%2").expect("a query");
    assert_eq!(form.malformed_pairs, 1);
    assert_eq!(form.fields.get("b").map(String::as_str), Some("100%"));
    assert_eq!(form.fields.get("c").map(String::as_str), Some("%zz"));
    assert_eq!(form.fields.get("d").map(String::as_str), Some("%2"));
}

/// The record is bounded and the evidence is not: a value past the ceiling is
/// cut on the record and whole in the body artifact, and the cut is counted.
#[test]
fn a_value_past_the_ceiling_is_cut_on_the_record_and_the_cut_is_counted() {
    let long = "x".repeat(MAX_FORM_VALUE_BYTES + 500);
    let form = query_fields(&format!("/a?note={long}")).expect("a query");
    assert_eq!(
        form.fields.get("note").map(String::len),
        Some(MAX_FORM_VALUE_BYTES)
    );
    assert_eq!(form.values_truncated, 1);

    let mut many = String::from("/a?");
    for n in 0..MAX_FORM_FIELDS + 3 {
        many.push_str(&format!("f{n}=1&"));
    }
    let form = query_fields(&many).expect("a query");
    assert_eq!(form.fields.len(), MAX_FORM_FIELDS);
    assert_eq!(form.fields_beyond_cap, 3);
}

// ── Framing rules that are about the status, not the headers ────────────────

/// **A 1xx, 204 or 304 response carries no body whatever its headers say**
/// (RFC 9112 §6.3). Reading one as if it did takes the next response as this
/// one's body and loses every message after it — and the ordinary
/// `Expect: 100-continue` exchange begins with exactly that.
#[test]
fn a_status_that_cannot_carry_a_body_is_not_given_one() {
    let stream = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    let out = parse_stream(stream, true);
    assert_eq!(out.messages.len(), 2, "both responses are read");
    assert_eq!(out.messages[0].status, Some(100));
    assert!(
        out.messages[0].body.is_empty(),
        "a 100 Continue has no body: {:?}",
        String::from_utf8_lossy(&out.messages[0].body)
    );
    assert_eq!(out.messages[0].body_end, BodyEnd::None);
    assert!(out.messages[0].is_whole());
    assert_eq!(out.messages[1].status, Some(200));
    assert_eq!(out.messages[1].body, b"hi");

    // 204 and 304 the same, and a Content-Length on a 304 describes the
    // representation that was NOT sent.
    for status in ["204 No Content", "304 Not Modified"] {
        let stream = format!(
            "HTTP/1.1 {status}\r\nContent-Length: 5\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
        );
        let out = parse_stream(stream.as_bytes(), true);
        assert_eq!(out.messages.len(), 2, "{status}");
        assert!(out.messages[0].body.is_empty(), "{status}");
        assert_eq!(out.messages[0].body_end, BodyEnd::None, "{status}");
        assert_eq!(out.messages[1].status, Some(200), "{status}");
    }
}

/// **A response to `HEAD` carries no body either**, however long it says its
/// representation is — so the answering direction can only be read correctly
/// beside the requests it answers.
#[test]
fn a_response_to_a_head_request_is_not_given_a_body() {
    let responses = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n\
                      HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    // Read without knowing the request, the declared thousand bytes swallow
    // what follows and the second response is lost.
    let blind = parse_stream(responses, true);
    assert_eq!(blind.messages.len(), 1);
    assert_eq!(
        blind.messages[0].body_end,
        BodyEnd::LengthShort {
            declared: 1000,
            present: 40
        }
    );

    // Read beside the methods, the HEAD's answer has no body and the next
    // response is read.
    let out = parse_stream_with_methods(responses, true, &["HEAD", "GET"]);
    assert_eq!(out.messages.len(), 2);
    assert!(out.messages[0].body.is_empty());
    assert_eq!(out.messages[0].body_end, BodyEnd::None);
    assert_eq!(
        out.messages[0].header("content-length"),
        Some("1000"),
        "what the representation WOULD have been is still on the record"
    );
    assert_eq!(out.messages[1].body, b"hi");
}

/// **A header continued on the next line is one header** (RFC 9112 §5.2's
/// obs-fold). Read as two, the second becomes a header nobody sent and the
/// first loses half its value.
#[test]
fn a_folded_header_line_is_joined_to_the_one_before_it() {
    let stream = b"HTTP/1.1 200 OK\r\n\
                   Set-Cookie: a=1; Expires=Wed, 09 Jun 2021\r\n\t10:18:14 GMT; Path=/\r\n\
                   Server: nginx\r\n\r\n";
    let out = parse_stream(stream, true);
    let m = &out.messages[0];
    assert_eq!(
        m.header("set-cookie"),
        Some("a=1; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Path=/"),
        "the fold becomes one space, as the RFC requires"
    );
    assert_eq!(m.header("server"), Some("nginx"));
    assert!(
        !m.headers.keys().any(|k| k.starts_with('\t') || k == "10"),
        "no header was invented out of the continuation: {:?}",
        m.headers.keys().collect::<Vec<_>>()
    );
    assert_eq!(m.headers_dropped, 0);
    assert_eq!(m.folded_headers, 1, "the fold itself is on the record");
    assert!(m.is_whole());
}

/// A chunked body's trailer is consumed with it, so the next message on the
/// connection is read rather than lost behind it.
#[test]
fn a_chunked_body_with_a_trailer_consumes_it_and_what_follows_is_read() {
    let stream = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                   5\r\nhello\r\n0\r\nExpires: Wed\r\nDigest: x\r\n\r\n\
                   HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    let out = parse_stream(stream, true);
    assert_eq!(
        out.messages.len(),
        2,
        "the trailer is not the end of reading"
    );
    assert_eq!(out.messages[0].body, b"hello");
    assert_eq!(out.messages[0].body_end, BodyEnd::ChunkedComplete);
    assert_eq!(out.messages[1].status, Some(404));
    assert_eq!(out.trailing_unparsed, 0);
}

/// **Two `Content-Length` headers that agree are one length; two that disagree
/// are a finding.** A disagreement is the classic request-smuggling signature,
/// and a parser that quietly picked one would hand an examiner one of the two
/// readings with nothing saying the other existed.
#[test]
fn content_lengths_that_agree_are_one_length_and_ones_that_disagree_are_a_finding() {
    let agreeing = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello\
                     HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    let out = parse_stream(agreeing, true);
    assert_eq!(out.messages.len(), 2);
    assert_eq!(out.messages[0].body, b"hello");
    assert_eq!(
        out.messages[0].body_end,
        BodyEnd::LengthSatisfied { declared: 5 }
    );

    let disagreeing = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\
                        Content-Length: 44\r\n\r\nhello";
    let out = parse_stream(disagreeing, true);
    let m = &out.messages[0];
    match &m.body_end {
        BodyEnd::LengthDisagreement { declared } => {
            assert!(
                declared.contains('5') && declared.contains("44"),
                "{declared}"
            )
        }
        other => panic!("{other:?}"),
    }
    assert!(!m.is_whole());
    assert!(
        m.body.is_empty(),
        "no framing was chosen, so no body is claimed"
    );
    assert_eq!(m.to_json()["body_end"], "length_disagreement");
}

// ── Bounds an attacker controls ─────────────────────────────────────────────

/// A start line as long as the stream is not a start line this build reads:
/// the header lines are bounded and so is this one, and the refusal is
/// reported rather than a sixty-megabyte "target" being put on a record.
#[test]
fn a_start_line_past_the_line_ceiling_is_refused_and_reported() {
    // Shaped so the sniff succeeds and the line does not: the version token
    // is inside the window `sniff` looks at, and the query string that
    // follows it runs for a megabyte before any terminator.
    let mut stream = b"GET /".to_vec();
    stream.extend(std::iter::repeat_n(b'A', 64));
    stream.extend_from_slice(b" HTTP/1.1");
    stream.extend_from_slice(b"?q=");
    stream.extend(std::iter::repeat_n(b'x', MAX_HEADER_LINE + 1024));
    stream.extend_from_slice(b"\r\nHost: h\r\n\r\n");
    assert_eq!(
        sniff(&stream),
        Some(Kind::Request),
        "the sniff does succeed"
    );
    let out = parse_stream(&stream, true);
    assert!(out.messages.is_empty(), "and nothing is read from it");
    assert!(out.start_line_too_long);
    assert_eq!(out.trailing_unparsed, stream.len() as u64);
}

/// A repeated header name grows one value, and the value stops at the header
/// block's own ceiling — otherwise `MAX_HEADERS` bounds the number of names
/// and nothing bounds the bytes.
#[test]
fn a_repeated_header_name_stops_growing_at_the_block_ceiling() {
    let mut stream = b"HTTP/1.1 200 OK\r\n".to_vec();
    let line: Vec<u8> = [b"x: ".as_slice(), &vec![b'A'; 4096], b"\r\n".as_slice()].concat();
    // Twice the block ceiling's worth of one repeated name.
    while stream.len() < MAX_HEADER_BYTES * 2 {
        stream.extend_from_slice(&line);
    }
    stream.extend_from_slice(b"\r\n");
    let out = parse_stream(&stream, true);
    let m = &out.messages[0];
    assert!(
        m.header("x").is_some_and(|v| v.len() <= MAX_HEADER_BYTES),
        "the value is bounded by the block ceiling"
    );
    assert!(m.headers_dropped > 0, "and what it cost is counted");
    assert!(!m.is_whole(), "a header set that is a prefix is not whole");
}

/// A form field's name is bounded like its value, and a repeated name stops
/// growing: the record is bounded and the body artifact holds everything.
#[test]
fn a_form_fields_name_is_bounded_and_a_repeat_stops_growing() {
    let long_name = "n".repeat(MAX_FORM_VALUE_BYTES + 100);
    let form = query_fields(&format!("/a?{long_name}=1")).expect("a query");
    assert_eq!(form.fields.len(), 1);
    assert!(form.fields.keys().all(|k| k.len() <= MAX_FORM_VALUE_BYTES));
    assert!(form.values_truncated > 0);

    let mut many = String::from("/a?");
    for _ in 0..4_000 {
        many.push_str(&format!("f={}&", "v".repeat(1000)));
    }
    let form = query_fields(&many).expect("a query");
    assert_eq!(form.fields.len(), 1, "one name");
    assert!(
        form.fields["f"].len() <= MAX_FORM_VALUE_BYTES,
        "and its joined value is bounded: {} bytes",
        form.fields["f"].len()
    );
    assert!(form.values_truncated > 0);
}

/// A chunk that declares more than the stream holds is still bounded by the
/// body ceiling, and what the ceiling cost is counted.
#[test]
fn a_truncated_chunk_respects_the_body_ceiling() {
    let mut stream = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    // One chunk claiming far more than follows, with more than the ceiling of
    // bytes after it.
    stream.extend_from_slice(b"7FFFFFFF\r\n");
    stream.extend(std::iter::repeat_n(b'A', MAX_BODY_BYTES + 4096));
    let out = parse_stream(&stream, false);
    let m = &out.messages[0];
    assert_eq!(
        m.body.len(),
        MAX_BODY_BYTES,
        "the ceiling is the ceiling, whichever path reached it"
    );
    assert!(m.body_capped);
    match m.body_end {
        BodyEnd::ChunkedTruncated { present } => assert!(
            present > MAX_BODY_BYTES as u64,
            "and what was present is reported, not what was kept: {present}"
        ),
        ref other => panic!("{other:?}"),
    }
    assert!(!m.is_whole());
}

/// A body cut by the wire ceiling is not a whole body, whatever its declared
/// length says.
#[test]
fn a_body_cut_by_the_wire_ceiling_is_not_whole() {
    let body_len = MAX_BODY_BYTES + 1024;
    let mut stream = format!("HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\n\r\n").into_bytes();
    stream.extend(std::iter::repeat_n(b'B', body_len));
    let out = parse_stream(&stream, true);
    let m = &out.messages[0];
    assert_eq!(m.body.len(), MAX_BODY_BYTES);
    assert!(m.body_capped);
    assert_eq!(
        m.body_end,
        BodyEnd::LengthSatisfied {
            declared: body_len as u64
        },
        "the stream did hold what was declared"
    );
    assert!(
        !m.is_whole(),
        "but the record holds a prefix of it, so nothing here is complete"
    );
    assert_eq!(m.to_json()["complete"], serde_json::json!(false));
}

/// A stream with more messages than this build parses says so, and the count
/// is what it parsed.
#[test]
fn a_stream_past_the_message_ceiling_says_so() {
    let one = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
    let mut stream = Vec::new();
    for _ in 0..MAX_MESSAGES_PER_STREAM + 4 {
        stream.extend_from_slice(one);
    }
    let out = parse_stream(&stream, true);
    assert_eq!(out.messages.len(), MAX_MESSAGES_PER_STREAM);
    assert!(out.message_cap_reached);
    assert!(out.trailing_unparsed > 0);
}

/// **A conversation whose start the capture does not hold gets its own
/// pairing.** There is no gap to count, and the response beside a request may
/// answer one sent before the capture began — which is a different fault from
/// a hole and must not read as an unqualified pairing.
#[test]
fn a_pairing_over_a_capture_that_began_mid_connection_says_so() {
    let requests = parse_stream(&request(), true).messages;
    let responses = parse_stream(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", true).messages;
    let paired = pair(
        requests,
        responses,
        Doubt {
            gaps: false,
            mid_connection: true,
        },
    );
    assert_eq!(paired.len(), 1);
    assert_eq!(paired[0].pairing, Pairing::InOrderFromAnIncompleteStart);
    let basis = paired[0].pairing.basis();
    assert!(basis.contains("DOES NOT HOLD THE START"), "{basis}");
    assert!(basis.contains("MAY BE WRONG"), "{basis}");
    assert_eq!(
        paired[0].pairing.as_str(),
        "in_order_from_an_incomplete_start"
    );
    // A gap is the worse fault and is the one reported where both apply.
    let over_both = pair(
        parse_stream(&request(), true).messages,
        Vec::new(),
        Doubt {
            gaps: true,
            mid_connection: true,
        },
    );
    assert_eq!(over_both[0].pairing, Pairing::RequestUnanswered);
}

// ── A tunnel is not a body ──────────────────────────────────────────────────

/// **A 2xx answer to `CONNECT` carries no body** (RFC 9112 §6.3 rule 1). What
/// follows it is the TUNNEL, and framing it as the response's content would
/// hand an examiner the proxied conversation's ciphertext as an HTTP body
/// artifact — filed under a content type and a URL that describe the request
/// rather than the bytes. This module's own documentation promises it does not
/// read a tunnel's payload; before this it did.
#[test]
fn a_tunnel_is_not_the_bodys_of_the_response_that_opened_it() {
    let responses = b"HTTP/1.1 200 Connection Established\r\n\r\n\
                      \x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03 tunnelled TLS bytes";
    let out = parse_stream_with_methods(responses, false, &["CONNECT"]);
    assert_eq!(out.messages.len(), 1);
    let m = &out.messages[0];
    assert_eq!(m.status, Some(200));
    assert!(
        m.body.is_empty(),
        "the tunnel is not this response's content: {:?}",
        String::from_utf8_lossy(&m.body)
    );
    assert_eq!(m.body_end, BodyEnd::None);
    // The tunnel's bytes are counted as unparsed rather than claimed.
    assert!(out.trailing_unparsed > 0);

    // Read without knowing the method, the framing falls back to the response's
    // own headers, which is the best that can be done and is why the two are
    // separate calls.
    let blind = parse_stream(responses, false);
    assert!(!blind.messages[0].body.is_empty());

    // A non-2xx answer to CONNECT is an ordinary response and may carry a body
    // explaining the refusal.
    let refused = b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 5\r\n\r\nnope!";
    let out = parse_stream_with_methods(refused, true, &["CONNECT"]);
    assert_eq!(out.messages[0].body, b"nope!");
}

/// **HTTP/2 is recognised even though it is not read.** HTTP/2 is most of the
/// web; a capture full of it would otherwise produce no HTTP records and
/// nothing anywhere saying HTTP/2 was present, which is "could not look"
/// rendering as "not there".
#[test]
fn an_http2_preface_is_recognised_and_counted_rather_than_passed_over() {
    let mut stream = HTTP2_PREFACE.to_vec();
    stream.extend_from_slice(&[0, 0, 12, 4, 0, 0, 0, 0, 0]); // a SETTINGS frame
    let out = parse_stream(&stream, false);
    assert!(out.http2_preface);
    assert!(
        out.messages.is_empty(),
        "and it is still not read as HTTP/1"
    );
    assert_eq!(sniff(&stream), None);

    // An HTTP/1 stream does not claim the preface.
    assert!(!parse_stream(&request(), true).http2_preface);
}
