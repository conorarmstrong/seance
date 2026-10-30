//! The capture module on DFIR Madness Case 001 ("The Stolen Szechuan Sauce"):
//! stage 1 (flows, DNS) and stage 2 (reassembly, HTTP, TLS, ARP) graded
//! against answers that do not come from Séance.
//!
//! # The capture
//!
//! `case001.pcap` (pcapng 1.0 despite the name, 197,583,252 bytes) from
//! `https://dfirmadness.com/case001/case001-pcap.zip`; the publisher's MD5 is
//! checked in `~/forensic_corpora/dfir_madness_case001/VERIFICATION.txt`. Unzip
//! it and point `SEANCE_CASE001_PCAP` at **the file** (the variable is the
//! path, not a directory). Unset, every test here prints a skip line and passes;
//! set to something that is not there, every test fails — the shared corpus
//! gate in `seance_core::test_support::corpus`.
//!
//! # Where each answer comes from
//!
//! - Packet, DNS, C2-flow and RDP figures: `tcpdump -nn -r case001.pcap` with a
//!   BPF filter per figure, run 2026-09-26 (tcpdump reads pcapng). The exact
//!   commands are in `documentation/VALIDATION.md` NET-4.
//! - The payload's hashes: the publisher's own `autorunsc` output in
//!   `DC01-autorunsc.zip` and `DESKTOP-SDN1RPT-autorunsc.zip`, which list the
//!   `coreupdater` service at `C:\Windows\System32\coreupdater.exe` with MD5
//!   `EED41B4500E473F97C50C7385EF5E374` and SHA-256 `10F3B920…0C1CFDA6` — read
//!   off the machines the payload landed on, by a tool that is not this one.
//!   Mind the columns: autorunsc prints `PESHA-256` (the Authenticode hash,
//!   `88763E60…E302FA28E`) immediately before `SHA-256`, and the file hash is
//!   the second of the two.
//! - The C2 address `203.78.103.109` and the delivery host `194.61.24.102`:
//!   the publisher's answer key.
//! - That the C2 on 443 is not TLS: the first bytes the C2 sends on each of its
//!   five connections are a 4-byte length (the Meterpreter stage size), read
//!   with `tcpdump -x`, not a TLS record header.
//!
//! Release-only: the whole capture is parsed once per test binary.

use std::sync::{Arc, OnceLock};

use md5::{Digest as _, Md5};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use serde_json::Value;
use sha2::Sha256;

const CASE001: &str = "SEANCE_CASE001_PCAP";
const C2: &str = "203.78.103.109";
const DELIVERY: &str = "194.61.24.102";

static RECORDS: OnceLock<Option<Vec<Artifact>>> = OnceLock::new();

/// Every record `PcapParser` emits over the capture, the way ingest drives it.
fn records() -> Option<&'static [Artifact]> {
    RECORDS
        .get_or_init(|| {
            let path = seance_core::test_support::corpus::path(CASE001)?;
            assert!(
                path.is_file(),
                "{CASE001} is set to {}, which is not a file. The gate is ON and cannot open.",
                path.display()
            );
            let source: Arc<dyn DataSource> = Arc::new(
                FileDataSource::new(path.clone())
                    .unwrap_or_else(|e| panic!("{} could not be opened: {e}", path.display())),
            );
            let artifact = Artifact::new(
                uuid::Uuid::new_v4(),
                ArtifactType::RawEvidence,
                Some(source),
                serde_json::json!({
                    "name": "case001.pcap",
                    "source_path": path.display().to_string(),
                }),
            );
            Some(
                seance_plugin_pcap::PcapParser
                    .process(&artifact)
                    .expect("the capture is processed"),
            )
        })
        .as_deref()
}

macro_rules! require {
    () => {
        match records() {
            Some(records) => records,
            None => return,
        }
    };
}

fn of_type<'a>(records: &'a [Artifact], ty: &str) -> Vec<&'a Artifact> {
    records
        .iter()
        .filter(|a| a.metadata["type"] == ty)
        .collect()
}

fn capture(records: &[Artifact]) -> &Value {
    let captures = of_type(records, "NetworkCapture");
    assert_eq!(captures.len(), 1, "one capture record");
    &captures[0].metadata
}

fn involves(flow: &Value, ip: &str) -> bool {
    flow["local_ip"] == ip || flow["remote_ip"] == ip
}

/// Stage 1, NET-1's figures, still true now that stage 2 runs beside it.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "parses a 197 MB capture; run with --release"
)]
fn case001_stage1_figures_hold() {
    let records = require!();
    let capture = capture(records);
    // tcpdump -nn -r case001.pcap | wc -l
    assert_eq!(capture["packets"], 411_797, "packets");
    // tcpdump -nn -r case001.pcap 'udp port 53' | wc -l
    assert_eq!(capture["dns_messages"], 2_650, "UDP/53 messages");
    assert_eq!(capture["dns_undecodable"], 0, "every DNS message decoded");
    // tcpdump ... 'udp port 53' | grep -E ' [0-9]+[+*]? ?update' | wc -l → 10
    let updates = of_type(records, "DnsResolution")
        .into_iter()
        .filter(|r| r.metadata["opcode"] == 5)
        .count();
    assert_eq!(updates, 10, "DNS UPDATE (opcode 5) messages");

    // tcpdump ... 'host 203.78.103.109' — 6,735 packets over five 5-tuples,
    // all on 443, first at 2020-09-19 02:25:18.565676.
    let c2: Vec<&Value> = of_type(records, "NetworkFlow")
        .into_iter()
        .map(|a| &a.metadata)
        .filter(|f| involves(f, C2))
        .collect();
    assert_eq!(c2.len(), 5, "five flows with the C2");
    let packets: u64 = c2.iter().map(|f| f["packets"].as_u64().unwrap()).sum();
    assert_eq!(packets, 6_735, "packets with the C2");
    assert!(
        c2.iter()
            .all(|f| f["remote_port"] == 443 && f["remote_ip"] == C2),
        "every C2 flow is to its port 443"
    );
    let first = c2
        .iter()
        .filter_map(|f| f["first_seen"].as_str())
        .min()
        .expect("a first contact");
    assert_eq!(
        first, "2020-09-19T02:25:18.565676Z",
        "first contact with the C2"
    );
}

/// The capture's record is complete only if nothing was left unread; a cap
/// that fired is stated on the record, never swallowed.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "parses a 197 MB capture; run with --release"
)]
fn every_tcp_conversation_is_reassembled_and_the_capture_is_whole() {
    let records = require!();
    let capture = capture(records);
    assert_eq!(
        capture["segments_beyond_tcp_stream_cap"], 0,
        "no TCP segment went unread for want of room in the stream table: {}",
        capture["inventory_incomplete_detail"]
    );
    assert_eq!(capture["tcp_stream_cap_reached"], false);
    assert!(
        capture["inventory_incomplete"] != true,
        "the capture carries no incompleteness stamp: {}",
        capture["inventory_incomplete_detail"]
    );
}

/// Stage 2: the implant crossing the wire is byte-for-byte the file autorunsc
/// hashed on the domain controller.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "parses a 197 MB capture; run with --release"
)]
fn the_implant_on_the_wire_is_the_file_on_disk() {
    let records = require!();
    let transaction = of_type(records, "HttpTransaction")
        .into_iter()
        .find(|t| {
            let m = &t.metadata;
            m["server_ip"] == DELIVERY
                && m["request"]["method"] == "GET"
                && m["request"]["target"] == "/coreupdater.exe"
        })
        .expect("the GET /coreupdater.exe from the delivery host is read");
    let m = &transaction.metadata;
    assert_eq!(m["server_port"], 80);
    assert_eq!(m["client_ip"], "10.42.85.10");
    assert_eq!(m["response"]["status"], 200);
    let body_id = m["response"]["body_artifact_id"]
        .as_str()
        .expect("the response body is handed on as an artifact");
    let body = records
        .iter()
        .find(|a| a.id.to_string() == body_id)
        .expect("the body artifact is emitted");
    assert_eq!(body.artifact_type, ArtifactType::FileEntry);
    assert!(
        body.metadata.get("content_incomplete").is_none(),
        "the body is whole: {}",
        body.metadata["content_incomplete"]
    );
    let data = body.data.as_ref().expect("the body carries its bytes");
    let bytes = seance_core::io::read_capped(data.as_ref(), u64::MAX);
    assert_eq!(bytes.len() as u64, data.size(), "read whole");
    let md5: String = Md5::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let sha256: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(md5, "eed41b4500e473f97c50c7385ef5e374", "MD5 per autorunsc");
    assert_eq!(
        sha256, "10f3b92002bb98467334161cf85d0b1730851f9256f83c27db125e9a0c1cfda6",
        "SHA-256 per autorunsc (its SHA-256 column, not PESHA-256)"
    );
}

/// The C2 speaks on 443 but not TLS. The module must not call it a session —
/// and must have looked: every C2 flow carries its reassembled streams, so
/// "no session" is a reading of the bytes, not an absence of them.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "parses a 197 MB capture; run with --release"
)]
fn the_c2_on_443_is_not_called_tls() {
    let records = require!();
    let c2_flows: Vec<&Value> = of_type(records, "NetworkFlow")
        .into_iter()
        .map(|a| &a.metadata)
        .filter(|f| involves(f, C2))
        .collect();
    assert_eq!(c2_flows.len(), 5);
    for flow in &c2_flows {
        assert!(
            flow.get("tcp_streams").is_some(),
            "the C2 flow from port {} was reassembled",
            flow["local_port"]
        );
    }
    let sessions: Vec<&Artifact> = of_type(records, "TlsSession")
        .into_iter()
        .filter(|s| s.metadata["server_ip"] == C2 || s.metadata["client_ip"] == C2)
        .collect();
    assert!(
        sessions.is_empty(),
        "no TLS session is claimed for the C2: {:?}",
        sessions
            .iter()
            .map(|s| &s.metadata["name"])
            .collect::<Vec<_>>()
    );
}

/// The RDP brute force from the delivery host, counted.
///
/// `tcpdump -nn -r case001.pcap 'host 194.61.24.102 and tcp port 3389'`,
/// folded to unordered 5-tuples, gives 14,116 conversations (29,309 SYNs,
/// because most were retried).
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "parses a 197 MB capture; run with --release"
)]
fn rdp_from_the_delivery_host_is_counted() {
    let records = require!();
    let rdp = of_type(records, "NetworkFlow")
        .into_iter()
        .map(|a| &a.metadata)
        .filter(|f| {
            f["protocol"] == "tcp"
                && involves(f, DELIVERY)
                && (f["local_port"] == 3389 || f["remote_port"] == 3389)
        })
        .count();
    assert_eq!(rdp, 14_116, "RDP conversations from the delivery host");
}

/// Every TLS session after the compromise has its record.
///
/// The session-record ceiling was 10,000. The capture holds 15,045
/// conversations that open a ClientHello before the first contact with the C2,
/// most of them the RDP brute force negotiating TLS, so the ceiling was spent
/// before the compromise and every session after it was parsed and given no
/// record. Reverting `tls::MAX_SESSIONS_PER_CAPTURE` to 10,000 fails this test.
///
/// # The answer, from tcpdump
///
/// The segments whose TCP payload begins with a TLS handshake record (content
/// type 22) carrying a ClientHello (handshake type 1):
///
/// ```text
/// TZ=UTC tcpdump -nn -tttt -r case001.pcap \
///   'tcp and tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16
///        and tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01' > ch.txt
/// awk '{print $4, $6}' ch.txt | sed 's/:$//' | sort -u | wc -l          # 15,360
/// awk '($1" "$2) <  "2020-09-19 02:25:18.565676" {print $4, $6}' ch.txt \
///   | sed 's/:$//' | sort -u | wc -l                                      # 15,045
/// awk '($1" "$2) >= "2020-09-19 02:25:18.565676" {print $4, $6}' ch.txt \
///   | sed 's/:$//' | sort -u | wc -l                                      # 316
/// ```
///
/// 30,554 segments, 15,360 distinct (source, destination) pairs; one pair,
/// `194.61.24.102.40240 > 10.42.85.10.3389`, is a reused port with a
/// ClientHello on each side of the split and so is in both counts.
///
/// # What Séance gives, and every difference accounted for
///
/// 15,356 sessions, each with its ClientHello read, placed on the timeline by
/// the first packet of the flow that carried it: 15,042 before and 314 after.
/// Diffing Séance's (client, server) pairs against tcpdump's leaves four
/// conversations with a ClientHello and no session — none the other way:
///
/// - `10.42.85.10:62514 → 10.42.85.115:3389` (after, 02:35:55), the RDP
///   session from the domain controller to the desktop. RDP sends its 19-byte
///   X.224 connection request before TLS, and TLS is recognised only at a
///   stream's first byte. Open defect PCAP-037.
/// - `194.61.24.102:{38088, 38092, 38100} → 10.42.85.10:3389` (before, 02:19
///   to 02:20): each 5-tuple was reused for two or three connections. The
///   first carried no TLS at its first byte (a reset before any payload, or the
///   X.224 request), and the later ones are folded into the first
///   connection's streams, where their ClientHellos are not at the start.
///   Open defect PCAP-038.
///
/// So 15,045 − 3 = 15,042 before, and 316 − 1 (62514) − 1 (40240, which
/// Séance places by its flow's first packet, before the split) = 314 after.
/// The two open defects are what these figures do not cover; when either is
/// fixed, these figures rise and the test must be re-derived, not re-typed.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "parses a 197 MB capture; run with --release"
)]
fn tls_sessions_after_the_compromise_have_records() {
    let records = require!();
    let mut first_seen = std::collections::HashMap::new();
    for flow in of_type(records, "NetworkFlow") {
        let f = &flow.metadata;
        if f["protocol"] != "tcp" {
            continue;
        }
        let a = format!("{}:{}", f["local_ip"].as_str().unwrap(), f["local_port"]);
        let b = format!("{}:{}", f["remote_ip"].as_str().unwrap(), f["remote_port"]);
        let seen = f["first_seen"].as_str().unwrap_or_default().to_string();
        first_seen.insert((a.clone(), b.clone()), seen.clone());
        first_seen.insert((b, a), seen);
    }
    let sessions = of_type(records, "TlsSession");
    assert_eq!(sessions.len(), 15_356, "TLS sessions with a record");
    let (mut before, mut after) = (0usize, 0usize);
    for s in &sessions {
        let m = &s.metadata;
        assert_eq!(m["client_hello_read"], true, "{}", m["name"]);
        let key = (
            format!("{}:{}", m["client_ip"].as_str().unwrap(), m["client_port"]),
            format!("{}:{}", m["server_ip"].as_str().unwrap(), m["server_port"]),
        );
        let seen = first_seen
            .get(&key)
            .unwrap_or_else(|| panic!("the session {key:?} has a flow"));
        if seen.as_str() >= "2020-09-19T02:25:18.565676Z" {
            after += 1;
        } else {
            before += 1;
        }
    }
    assert_eq!(
        after, 314,
        "sessions with a record after the C2's first contact"
    );
    assert_eq!(before, 15_042, "sessions with a record before it");
}
