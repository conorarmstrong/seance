//! The TLS reader, graded against OpenSSL over the same bytes.
//!
//! The four fixtures are real handshakes (`tests/fixtures/README.md`). The
//! oracle for the ClientHello fields is `openssl s_client -trace`, which
//! prints OpenSSL's own decode of the same message:
//!
//! ```text
//! ClientHello, Length=209
//!   client_version=0x303 (TLS 1.2)
//!   cipher_suites (len=54)   -- 27 suites, {0xC0,0x2C} first, {0x00,0x2F} last
//!   extensions: renegotiate(65281) server_name(0) ec_point_formats(11)
//!               supported_groups(10) session_ticket(35) encrypt_then_mac(22)
//!               extended_master_secret(23) signature_algorithms(13)
//!   server_name: lab.seance.invalid
//!   supported_groups: 29 23 30 24 25       ec_point_formats: 0 1 2
//! ```
//!
//! and for the certificate, `openssl x509 -text` (see `x509_tests.rs`).

use super::*;

const TLS12_CLIENT: &[u8] = include_bytes!("../tests/fixtures/tls12_client_to_server.bin");
const TLS12_SERVER: &[u8] = include_bytes!("../tests/fixtures/tls12_server_to_client.bin");
const TLS13_CLIENT: &[u8] = include_bytes!("../tests/fixtures/tls13_client_to_server.bin");
const TLS13_SERVER: &[u8] = include_bytes!("../tests/fixtures/tls13_server_to_client.bin");

// ── Recognised by its own bytes ─────────────────────────────────────────────

/// **A TLS stream is recognised by its record header and its first handshake
/// byte**, on any port — a C2 on 8080 is still TLS — and a great deal of
/// binary traffic begins with a byte that is not 22.
#[test]
fn a_stream_is_recognised_as_tls_by_its_record_and_handshake_bytes() {
    assert_eq!(sniff(TLS12_CLIENT), Some(Side::Client));
    assert_eq!(sniff(TLS12_SERVER), Some(Side::Server));
    assert_eq!(sniff(TLS13_CLIENT), Some(Side::Client));
    assert_eq!(sniff(TLS13_SERVER), Some(Side::Server));
    // Not TLS: HTTP, an empty stream, a record with a version no TLS ever
    // used, and a handshake type that is neither hello.
    assert_eq!(sniff(b"GET / HTTP/1.1\r\n"), None);
    assert_eq!(sniff(b""), None);
    assert_eq!(sniff(&[0x16, 0x09, 0x01, 0x00, 0x10, 0x01]), None);
    assert_eq!(sniff(&[0x16, 0x03, 0x01, 0x00, 0x10, 0x0b]), None);
    // A record header with nothing after it states nothing.
    assert_eq!(sniff(&[0x16, 0x03, 0x01, 0x00, 0x10]), None);
}

// ── The ClientHello ─────────────────────────────────────────────────────────

/// Every field OpenSSL's own decode prints for this ClientHello, read from
/// the same bytes.
#[test]
fn the_client_hello_is_read_as_openssl_reads_the_same_bytes() {
    let side = read_direction(TLS12_CLIENT).expect("a TLS direction");
    let hello = side.client_hello.as_ref().expect("a ClientHello");
    assert_eq!(hello.legacy_version, 0x0303);
    assert_eq!(hello.server_name.as_deref(), Some("lab.seance.invalid"));
    assert_eq!(hello.cipher_suites.len(), 27);
    assert_eq!(hello.cipher_suites.first(), Some(&0xC02C));
    assert_eq!(hello.cipher_suites.last(), Some(&0x002F));
    assert_eq!(
        hello.extensions,
        vec![65281, 0, 11, 10, 35, 22, 23, 13],
        "in the order they were sent, which is what a fingerprint is of"
    );
    assert_eq!(hello.supported_groups, vec![29, 23, 30, 24, 25]);
    assert_eq!(hello.ec_point_formats, vec![0, 1, 2]);
    assert!(hello.alpn.is_empty(), "this client offered none");
    assert!(
        hello.supported_versions.is_empty(),
        "a TLS 1.2 client states its version in the legacy field"
    );
    assert_eq!(hello.grease_values, 0);
    assert!(!hello.encrypted_client_hello);
}

/// **JA3**, the client fingerprint, built from the five field lists in the
/// specification's order. Graded against the same lists taken from OpenSSL's
/// decode, and the digest against `openssl md5` of that string.
#[test]
fn the_client_fingerprint_is_the_ja3_of_the_fields_openssl_decoded() {
    let side = read_direction(TLS12_CLIENT).expect("a TLS direction");
    let hello = side.client_hello.as_ref().expect("a ClientHello");
    assert_eq!(
        hello.ja3,
        "771,49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-\
         49162-49172-57-49161-49171-51-157-156-61-60-53-47,65281-0-11-10-35-22-23-13,\
         29-23-30-24-25,0-1-2"
    );
    assert_eq!(hello.ja3_md5, "1c9a15ffefdbe3d51d703fde3c4086eb");
}

/// A TLS 1.3 client states its version in an extension, offers ALPN, and its
/// fingerprint is a different one.
#[test]
fn a_tls13_client_hello_carries_its_version_and_alpn_in_extensions() {
    let side = read_direction(TLS13_CLIENT).expect("a TLS direction");
    let hello = side.client_hello.as_ref().expect("a ClientHello");
    assert_eq!(
        hello.legacy_version, 0x0303,
        "the record and the legacy field both say 1.2; the extension is where 1.3 is stated"
    );
    assert_eq!(hello.supported_versions, vec![0x0304]);
    assert_eq!(hello.highest_version_offered(), Some(0x0304));
    assert_eq!(hello.server_name.as_deref(), Some("lab.seance.invalid"));
    assert_eq!(hello.alpn, vec!["h2", "http/1.1"]);
    assert_eq!(hello.cipher_suites, vec![4866, 4867, 4865]);
    assert_eq!(hello.ja3_md5, "036bfa3a293e8fb976317efd97d7d778");
}

// ── The ServerHello, and what the server proved ─────────────────────────────

/// The negotiated cipher is the one the client's own log named
/// (`ECDHE-RSA-AES256-GCM-SHA384`, 0xC030), and the version is the legacy
/// field because no extension overrode it.
#[test]
fn the_server_hello_names_the_version_and_cipher_that_were_negotiated() {
    let side = read_direction(TLS12_SERVER).expect("a TLS direction");
    let hello = side.server_hello.as_ref().expect("a ServerHello");
    assert_eq!(hello.legacy_version, 0x0303);
    assert_eq!(hello.negotiated_version(), 0x0303);
    assert_eq!(version_name(hello.negotiated_version()), "TLS 1.2");
    assert_eq!(hello.cipher_suite, 0xC030);
    assert_eq!(
        cipher_name(hello.cipher_suite),
        Some("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
    );
    assert!(hello.alpn.is_none());
}

/// **The certificate the server presented, read out of the capture.** The
/// chain, its names, and the digest that identifies it — all from the bytes,
/// and all matching what `openssl x509` reads from the same certificate.
#[test]
fn the_servers_certificate_is_read_from_the_capture_with_its_names() {
    let side = read_direction(TLS12_SERVER).expect("a TLS direction");
    assert_eq!(side.certificates.len(), 1);
    let certificate =
        crate::x509::Certificate::parse(&side.certificates[0]).expect("the certificate parses");
    assert_eq!(
        certificate.subject_common_name.as_deref(),
        Some("lab.seance.invalid")
    );
    assert_eq!(
        certificate.names(),
        vec!["lab.seance.invalid", "alt.seance.invalid", "127.0.0.1"]
    );
    assert_eq!(
        certificate.sha256,
        "e0e0bc2fee38697c255da4b4115def0a5702b7b9dd05066d801c09e862ca875a"
    );
    assert!(certificate.self_signed);
    assert!(side.certificate_chain_complete);
}

/// **TLS 1.3 encrypts the certificate, and the record says so rather than
/// showing an empty chain.** "No certificate was seen" and "the certificate
/// cannot be seen in this version" are different findings, and only one of
/// them is a fact about the server.
#[test]
fn a_tls13_server_gives_no_certificate_and_the_reason_is_recorded() {
    let side = read_direction(TLS13_SERVER).expect("a TLS direction");
    let hello = side.server_hello.as_ref().expect("a ServerHello");
    assert_eq!(hello.negotiated_version(), 0x0304);
    assert_eq!(version_name(hello.negotiated_version()), "TLS 1.3");
    assert_eq!(hello.cipher_suite, 4866);
    assert!(side.certificates.is_empty());
    assert_eq!(
        side.certificates_unavailable(),
        Some(CertificatesUnavailable::EncryptedByTls13)
    );
    assert!(side
        .certificates_unavailable()
        .expect("a reason")
        .statement()
        .contains("TLS 1.3"));
}

// ── Where the cleartext ends ────────────────────────────────────────────────

/// **The handshake is read up to the change of cipher and not past it.** What
/// follows is encrypted, and a record showing it as unparsed handshake would
/// invite the reader to think something was missed.
#[test]
fn reading_stops_where_the_cipher_changes_and_the_rest_is_counted() {
    let side = read_direction(TLS12_CLIENT).expect("a TLS direction");
    assert_eq!(side.records, 6, "every record is walked and counted");
    assert_eq!(side.change_cipher_spec_at, Some(260));
    assert_eq!(
        side.handshake_messages, 2,
        "the ClientHello and the ClientKeyExchange, in the clear"
    );
    assert_eq!(
        side.encrypted_records, 3,
        "a handshake record, an application-data record and an alert, all after the change"
    );
    assert_eq!(side.stop, Stop::EndOfPrefix);
    assert!(side.is_complete());
}

/// A prefix that ends inside a record says where, and does not read the
/// partial record as if its bytes were all there.
#[test]
fn a_prefix_that_ends_inside_a_record_says_where_it_ended() {
    let cut = &TLS12_SERVER[..40];
    let side = read_direction(cut).expect("a TLS direction");
    assert_eq!(
        side.stop,
        Stop::PartialRecord {
            at: 0,
            declared: 65,
            present: 35
        }
    );
    assert!(side.server_hello.is_none(), "not read from 35 of 65 bytes");
    assert!(!side.is_complete());
    assert!(side.stop.statement().contains("ended inside"));
}

/// A handshake message split across records is put back together before it is
/// read: a certificate chain that does not fit one record is the ordinary case
/// on a real server.
#[test]
fn a_handshake_message_split_across_records_is_read_whole() {
    // The server's first two records hold the ServerHello and the
    // Certificate; re-frame their payloads into 200-byte records, which is
    // what a small MTU or a deliberate splitter produces.
    let mut payload = Vec::new();
    let mut rest = TLS12_SERVER;
    for _ in 0..2 {
        let length = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        payload.extend_from_slice(&rest[5..5 + length]);
        rest = &rest[5 + length..];
    }
    let mut split = Vec::new();
    for chunk in payload.chunks(200) {
        split.extend_from_slice(&[0x16, 0x03, 0x03]);
        split.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        split.extend_from_slice(chunk);
    }
    let side = read_direction(&split).expect("a TLS direction");
    assert!(side.records > 2, "re-framed into more records than before");
    assert_eq!(side.handshake_messages, 2);
    assert_eq!(side.certificates.len(), 1, "the chain spans records");
    assert!(side.server_hello.is_some());
    assert!(side.is_complete());
}

/// A record that claims more than a TLS record may hold is refused, and the
/// refusal names the number the record claimed. The ceiling is the largest a
/// protected record may be -- 2^14 of plaintext plus the 2048 bytes RFC 5246
/// and RFC 8446 allow for expansion -- so a record between the two is waited
/// on and only one above it is refused.
#[test]
fn a_record_longer_than_tls_allows_is_refused_and_one_merely_cut_is_waited_on() {
    // Both cases begin with this conversation's real ClientHello record, so
    // the stream is TLS and the question is what the SECOND record does.
    let hello = &TLS12_CLIENT[..218];

    let mut hostile = hello.to_vec();
    hostile.extend_from_slice(&[0x16, 0x03, 0x03, 0xff, 0xff]);
    hostile.extend_from_slice(&[0u8; 16]);
    let side = read_direction(&hostile).expect("a TLS direction");
    assert_eq!(
        side.stop,
        Stop::RecordTooLong {
            at: 218,
            declared: 65535
        }
    );
    assert!(side.stop.statement().contains("65535"));
    assert!(
        side.client_hello.is_some(),
        "what was read before the refusal is still read"
    );

    // 16385 bytes is over the plaintext limit and inside the expansion
    // allowance: a legitimate protected record, simply cut by the prefix.
    let mut cut = hello.to_vec();
    cut.extend_from_slice(&[0x16, 0x03, 0x03, 0x40, 0x01]);
    cut.extend_from_slice(&[0u8; 16]);
    let side = read_direction(&cut).expect("a TLS direction");
    assert_eq!(
        side.stop,
        Stop::PartialRecord {
            at: 218,
            declared: 16385,
            present: 16
        }
    );
}

/// Bytes that are not a record header where a record should begin stop the
/// walk there, and what was read before them is kept: the stream WAS TLS, and
/// that is a different statement from "these bytes are not TLS".
#[test]
fn foreign_bytes_after_a_record_stop_the_walk_where_they_begin() {
    let mut mixed = TLS12_CLIENT[..218].to_vec();
    mixed.extend_from_slice(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
    let side = read_direction(&mixed).expect("a TLS direction");
    assert_eq!(side.stop, Stop::NotARecord { at: 218 });
    assert!(side.client_hello.is_some());
    assert!(!side.is_complete());
}

/// Bytes that are not TLS yield nothing at all, rather than a session record
/// with every field empty.
#[test]
fn bytes_that_are_not_tls_yield_no_direction() {
    assert!(read_direction(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").is_none());
    assert!(read_direction(b"").is_none());
    assert!(read_direction(&[0u8; 64]).is_none());
}

/// A GREASE value is not a cipher, a group or an extension anybody
/// implements: it is a value a browser sends to keep middleboxes honest, and
/// counting it would make every Chrome fingerprint unique.
#[test]
fn grease_values_are_counted_and_left_out_of_the_fingerprint() {
    // A minimal ClientHello: one GREASE cipher, one real one, one GREASE
    // extension and one real one.
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]); // legacy version
    hello.extend_from_slice(&[0x11; 32]); // random
    hello.push(0); // no session id
    hello.extend_from_slice(&[0x00, 0x04]); // two cipher suites
    hello.extend_from_slice(&[0x0a, 0x0a, 0x13, 0x01]);
    hello.extend_from_slice(&[0x01, 0x00]); // one compression method
    let extensions: Vec<u8> = vec![
        0x1a, 0x1a, 0x00, 0x00, // GREASE extension, empty
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, // ec_point_formats: [0]
    ];
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut message = vec![0x01];
    message.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    message.extend_from_slice(&hello);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(message.len() as u16).to_be_bytes());
    record.extend_from_slice(&message);

    let side = read_direction(&record).expect("a TLS direction");
    let parsed = side.client_hello.as_ref().expect("a ClientHello");
    assert_eq!(
        parsed.cipher_suites,
        vec![0x1301],
        "the GREASE one is not a cipher"
    );
    assert_eq!(parsed.extensions, vec![11]);
    assert_eq!(parsed.grease_values, 2);
    assert_eq!(parsed.ja3, "771,4865,11,,0");
}

// ── The reasons that had no test ────────────────────────────────────────────

/// **A TLS 1.2 session with no certificate in the cleartext is a different
/// finding from a TLS 1.3 one**, and each says which applies. A resumed
/// session, a handshake that failed before the certificate, and a capture
/// that lost the bytes carrying it all reach this one.
#[test]
fn a_session_with_no_certificate_before_tls13_says_the_cleartext_held_none() {
    // The server's first record only: a ServerHello and nothing after it.
    let length = usize::from(u16::from_be_bytes([TLS12_SERVER[3], TLS12_SERVER[4]]));
    let hello_only = &TLS12_SERVER[..5 + length];
    let side = read_direction(hello_only).expect("a TLS direction");
    assert!(side.server_hello.is_some());
    assert!(side.certificates.is_empty());
    assert_eq!(
        side.certificates_unavailable(),
        Some(CertificatesUnavailable::NotInTheCleartext)
    );
    let statement = side
        .certificates_unavailable()
        .expect("a reason")
        .statement();
    assert!(statement.contains("resumed"), "{statement}");
    assert!(
        statement.contains("missing from the capture"),
        "{statement}"
    );
    assert_eq!(
        CertificatesUnavailable::NotInTheCleartext.as_str(),
        "not_in_the_cleartext"
    );
}

/// Every stop reason has a token and a sentence, and the two ceilings that
/// bound the walk are reachable rather than decorative.
#[test]
fn the_walk_stops_at_its_ceilings_and_every_reason_has_a_token() {
    assert_eq!(Stop::EndOfPrefix.as_str(), "end_of_prefix");
    assert_eq!(
        Stop::PartialRecord {
            at: 1,
            declared: 2,
            present: 3
        }
        .as_str(),
        "partial_record"
    );
    assert_eq!(
        Stop::RecordTooLong { at: 1, declared: 2 }.as_str(),
        "record_too_long"
    );
    assert_eq!(Stop::NotARecord { at: 1 }.as_str(), "not_a_record");
    assert_eq!(Stop::RecordCeiling { at: 1 }.as_str(), "record_ceiling");
    assert_eq!(
        Stop::HandshakeCeiling { at: 1 }.as_str(),
        "handshake_ceiling"
    );

    // The record ceiling: the ClientHello, then more records than the walk
    // will take. Each is a one-byte application-data record, which is
    // legitimate framing and the cheapest way to reach the ceiling.
    let mut many = TLS12_CLIENT[..218].to_vec();
    for _ in 0..MAX_RECORDS {
        many.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]);
    }
    let side = read_direction(&many).expect("a TLS direction");
    assert_eq!(side.records, MAX_RECORDS);
    match side.stop {
        Stop::RecordCeiling { at } => assert!(at > 0, "the offset it stopped at: {at}"),
        ref other => panic!("{other:?}"),
    }
    assert!(!side.is_complete());
    assert!(side.stop.statement().contains(&MAX_RECORDS.to_string()));

    // The handshake ceiling: handshake records whose payloads add up past
    // what this build will assemble.
    let mut long = Vec::new();
    let payload = vec![0u8; 16_384];
    let mut first = TLS12_CLIENT[..218].to_vec();
    long.append(&mut first);
    while long.len() < MAX_HANDSHAKE_BYTES + 32_768 {
        long.extend_from_slice(&[0x16, 0x03, 0x03]);
        long.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        long.extend_from_slice(&payload);
    }
    let side = read_direction(&long).expect("a TLS direction");
    match side.stop {
        Stop::HandshakeCeiling { at } => assert!(at > 0, "{at}"),
        ref other => panic!("{other:?}"),
    }
    assert!(!side.is_complete());
    assert!(side
        .stop
        .statement()
        .contains(&MAX_HANDSHAKE_BYTES.to_string()));
    // What was read before the ceiling is still read.
    assert!(side.client_hello.is_some());
}

/// **A session with no `ServerHello` in the cleartext is a third state, and it
/// says so.** Before this it carried no reason at all, which reads as a server
/// that presented no certificate — and three documents promised the record
/// says "which of the two reasons applies".
#[test]
fn a_direction_with_no_server_hello_states_that_rather_than_nothing() {
    // The client's direction: a ClientHello and no answer in it at all.
    let side = read_direction(TLS12_CLIENT).expect("a TLS direction");
    assert!(side.server_hello.is_none());
    assert!(side.certificates.is_empty());
    assert_eq!(
        side.certificates_unavailable(),
        Some(CertificatesUnavailable::NoServerHello)
    );
    let statement = side
        .certificates_unavailable()
        .expect("a reason")
        .statement();
    assert!(
        statement.contains("SAYS NOTHING ABOUT WHAT THE SERVER PRESENTED"),
        "{statement}"
    );
    assert_eq!(
        CertificatesUnavailable::NoServerHello.as_str(),
        "no_server_hello_in_the_cleartext"
    );
    // And the three reasons are three: none of them renders as another.
    let all = [
        CertificatesUnavailable::EncryptedByTls13,
        CertificatesUnavailable::NotInTheCleartext,
        CertificatesUnavailable::NoServerHello,
    ];
    let tokens: std::collections::BTreeSet<&str> = all.iter().map(|r| r.as_str()).collect();
    assert_eq!(tokens.len(), 3);
}

/// **Every conversation the stream table can hold can have its session
/// record.** The TLS record ceiling was 10,000 against a stream table of
/// 262,144 streams (131,072 conversations), and on DFIR Madness Case 001 an RDP
/// brute force negotiated TLS on some fourteen thousand connections: the
/// ceiling was spent on the brute force and every session after it in the
/// capture — the whole post-compromise period — was read and given no record.
/// The sessions are parsed and held either way; the ceiling bounds only the
/// records, and it must not be tighter than the table that feeds it.
#[test]
fn the_session_record_ceiling_is_not_tighter_than_the_stream_table() {
    // Read through `black_box` so the check stays a test that runs, rather
    // than a constant the linter asks to be folded away.
    let records = std::hint::black_box(MAX_SESSIONS_PER_CAPTURE);
    let conversations = std::hint::black_box(crate::reassemble::MAX_STREAMS) / 2;
    assert!(
        records >= conversations,
        "{records} session records for {conversations} conversations"
    );
}
