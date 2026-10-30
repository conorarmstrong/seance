//! Regression pins for reproducers the fuzzer once found (FUZZ-ARTIFACTS).
//!
//! Each input replayed clean at 3eb34ba3 (2026-10-20) before it was pinned
//! here; these are regression pins, not red-first tests. The harness below
//! mirrors fuzz/fuzz_targets/ext4_parser.rs. The module runs on its own thread
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
        let buf = input.to_vec();
        let ds = Arc::new(ByteSliceDataSource::new(buf));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(ds),
            serde_json::json!({"name": "fuzz", "subtype": "ext4"}),
        );
        let module = seance_plugin_ext4::Ext4Parser::new();
        // Ok or Err are both acceptable; a panic drops tx and fails recv.
        let _ = module.process(&artifact);
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(30))
        .expect("module must return without panic or hang");
}

#[test]
fn fuzz_reproducer_ext4_crash_41c0b3f4_does_not_panic() {
    replay(include_bytes!(
        "fixtures/fuzz/crash-41c0b3f48be9d5e9296483ab1004831d00ca1eb1"
    ));
}
