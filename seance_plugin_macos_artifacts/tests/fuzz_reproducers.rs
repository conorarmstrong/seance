//! Regression pin for a reproducer the fuzzer once found (FUZZ-ARTIFACTS).
//!
//! The input replayed clean at 3eb34ba3 (2026-10-20) before it was pinned
//! here; this is a regression pin, not a red-first test. The harness mirrors
//! all five steps of fuzz/fuzz_targets/unifiedlog_tracev3.rs, on its own
//! thread with a join timeout so a hang fails the test.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::ByteSliceDataSource,
    module::ForensicsModule,
};
use std::sync::{mpsc, Arc};
use std::time::Duration;
use uuid::Uuid;

fn run(module: &dyn ForensicsModule, bytes: Vec<u8>, name: &str) {
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ByteSliceDataSource::new(bytes))),
        serde_json::json!({ "name": name }),
    );
    let _ = module.process(&artifact);
}

fn chunk(tag: u32, payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(payload);
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
}

fn replay(data: &'static [u8]) {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let tracev3 = seance_plugin_macos_artifacts::UnifiedLogParser;

        let mut file = Vec::new();
        chunk(0x1000, &[], &mut file);
        file.extend_from_slice(data);
        run(&tracev3, file, "fuzz.tracev3");

        let mut block = b"bv4-".to_vec();
        block.extend_from_slice(&(data.len() as u32).to_le_bytes());
        block.extend_from_slice(data);
        block.extend_from_slice(b"bv4$");
        let mut file = Vec::new();
        chunk(0x1000, &[], &mut file);
        chunk(0x600d, &block, &mut file);
        run(&tracev3, file, "fuzz.tracev3");

        let mut file = Vec::new();
        chunk(0x1000, &[], &mut file);
        chunk(0x600b, data, &mut file);
        run(&tracev3, file, "fuzz.tracev3");

        seance_plugin_macos_artifacts::fuzz_unifiedlog_parts(data);

        run(
            &seance_plugin_macos_artifacts::UnifiedLogTimesyncParser,
            data.to_vec(),
            "fuzz.timesync",
        );
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(30))
        .expect("unified-log readers must return without panic or hang");
}

#[test]
fn fuzz_reproducer_unifiedlog_crash_b6cb3b1f_does_not_panic() {
    replay(include_bytes!(
        "fixtures/fuzz/crash-b6cb3b1f2196243d54e0d00967e76da46b30b71b"
    ));
}
