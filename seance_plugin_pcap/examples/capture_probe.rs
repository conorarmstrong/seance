//! Known-answer probe: run the module over a capture file and summarise what it emits.
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use std::collections::BTreeMap;
use std::sync::Arc;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: capture_probe <file>");
    let src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(path.clone().into()).expect("open"));
    let name = std::path::Path::new(&path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(src),
        serde_json::json!({ "name": name, "source_path": path }),
    );
    let started = std::time::Instant::now();
    let out = seance_plugin_pcap::PcapParser
        .process(&artifact)
        .expect("process");
    let elapsed = started.elapsed();
    let mut by_type: BTreeMap<String, usize> = BTreeMap::new();
    for a in &out {
        let t = a
            .metadata
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or(&format!("{:?}", a.artifact_type))
            .to_string();
        *by_type.entry(t).or_default() += 1;
    }
    println!("elapsed {:?}", elapsed);
    println!("records by type: {by_type:?}");
    for a in &out {
        if a.metadata.get("type").and_then(|v| v.as_str()) == Some("NetworkCapture") {
            println!(
                "capture: {}",
                serde_json::to_string_pretty(&a.metadata).unwrap()
            );
        }
    }
    // What the reassembled streams said, which is what stage 2 added. Printed
    // as counts plus a handful of examples: a 94,000-packet capture holds
    // thousands of transactions and the point of a probe is the figures.
    let of = |ty: &str| -> Vec<&Artifact> {
        out.iter()
            .filter(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some(ty))
            .collect()
    };
    let transactions = of("HttpTransaction");
    println!("\nHTTP: {} transactions", transactions.len());
    let mut hosts: BTreeMap<String, usize> = BTreeMap::new();
    let mut with_forms = 0usize;
    for t in &transactions {
        if let Some(host) = t.metadata["host"].as_str() {
            *hosts.entry(host.to_string()).or_default() += 1;
        }
        if !t.metadata["request"]["form_fields"].is_null() {
            with_forms += 1;
        }
    }
    let mut by_count: Vec<(&String, &usize)> = hosts.iter().collect();
    by_count.sort_by(|a, b| b.1.cmp(a.1));
    println!("  distinct hosts: {}", hosts.len());
    for (host, count) in by_count.iter().take(10) {
        println!("    {count:>6}  {host}");
    }
    println!("  transactions with a decoded form: {with_forms}");
    for t in transactions.iter().filter(|t| {
        t.metadata["request"]["form_fields"]["field_count"]
            .as_u64()
            .unwrap_or(0)
            > 0
    }) {
        println!(
            // forensic-lint: allow RAGGED-STRING — indented continuation line in probe output.
            "    POST {} -> {}\n      fields {}",
            t.metadata["url"],
            t.metadata["response"]["status"],
            t.metadata["request"]["form_fields"]["fields"]
        );
    }
    let bodies = out
        .iter()
        .filter(|a| a.metadata.get("http_body").is_some())
        .count();
    println!("  bodies handed on as artifacts: {bodies}");

    let sessions = of("TlsSession");
    let mut names: BTreeMap<String, usize> = BTreeMap::new();
    for s in &sessions {
        if let Some(name) = s.metadata["server_name"].as_str() {
            *names.entry(name.to_string()).or_default() += 1;
        }
    }
    let mut by_count: Vec<(&String, &usize)> = names.iter().collect();
    by_count.sort_by(|a, b| b.1.cmp(a.1));
    println!(
        "\nTLS: {} sessions, {} distinct server names",
        sessions.len(),
        names.len()
    );
    for (name, count) in by_count.iter().take(20) {
        println!("    {count:>6}  {name}");
    }
    let certificates = of("TlsCertificate");
    println!("  certificates read: {}", certificates.len());
    for c in certificates.iter().take(10) {
        println!(
            "    {} (issuer {}, self-signed {})",
            c.metadata["subject"], c.metadata["issuer"], c.metadata["self_signed"]
        );
    }

    let bindings = of("ArpBinding");
    let contested: Vec<&&Artifact> = bindings
        .iter()
        .filter(|b| b.metadata["contested"] == serde_json::json!(true))
        .collect();
    println!(
        "\nARP: {} bindings, {} contested",
        bindings.len(),
        contested.len()
    );
    for b in &bindings {
        println!("    {} {}", b.metadata["ip"], b.metadata["macs"]);
    }
    for b in &contested {
        println!(
            "  contested: {}",
            serde_json::to_string(&b.metadata).unwrap()
        );
    }

    let target = std::env::args().nth(2);
    if let Some(t) = target {
        let mut hits: Vec<&Artifact> = out
            .iter()
            .filter(|a| {
                a.metadata.get("type").and_then(|v| v.as_str()) == Some("NetworkFlow")
                    && (a.metadata.get("remote_ip").and_then(|v| v.as_str()) == Some(&t)
                        || a.metadata.get("local_ip").and_then(|v| v.as_str()) == Some(&t))
            })
            .collect();
        hits.sort_by_key(|a| {
            std::cmp::Reverse(
                a.metadata
                    .get("packets")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            )
        });
        println!("flows involving {t}: {}", hits.len());
        for a in hits.iter().take(8) {
            let m = &a.metadata;
            println!(
                "  {} {}:{} <-> {}:{} pkts {} bytes {} first {} state {} ext {}",
                m["protocol"],
                m["local_ip"],
                m["local_port"],
                m["remote_ip"],
                m["remote_port"],
                m["packets"],
                m["bytes"],
                m["first_seen"],
                m["tcp_state"],
                m["remote_is_external"]
            );
        }
    }
}
