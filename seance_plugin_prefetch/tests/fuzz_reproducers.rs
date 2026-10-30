//! Regression pins for reproducers the fuzzer once found (FUZZ-ARTIFACTS).
//!
//! Each input replayed clean at 3eb34ba3 (2026-10-20) before it was pinned
//! here; these are regression pins, not red-first tests. The harness below
//! mirrors fuzz/fuzz_targets/prefetch_parser.rs. The module runs on its own thread
//! with a join timeout, so a hang or runaway allocation fails the test
//! instead of stalling the suite.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::ByteSliceDataSource,
    module::ForensicsModule,
};
use std::sync::{mpsc, Arc};
use std::time::Duration;
use uuid::Uuid;

fn replay(input: &'static [u8]) {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::with_capacity(8 + input.len());
        buf.extend_from_slice(&17u32.to_le_bytes());
        buf.extend_from_slice(b"SCCA");
        buf.extend_from_slice(input);
        let ds = Arc::new(ByteSliceDataSource::new(buf));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::SystemArtifact,
            Some(ds),
            serde_json::json!({"name": "fuzz_input"}),
        );
        let module = seance_plugin_prefetch::PrefetchParser;
        // Ok or Err are both acceptable; a panic drops tx and fails recv.
        let _ = module.process(&artifact);
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(30))
        .expect("module must return without panic or hang");
}

#[test]
fn fuzz_reproducer_prefetch_oom_5dd80641_does_not_panic() {
    replay(include_bytes!(
        "fixtures/fuzz/oom-5dd806410890d7d3069584ab243c4824dd2179d1"
    ));
}
