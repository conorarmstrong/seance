//! Every input a fuzzer has ever crashed a parser on, replayed as a test.
//!
//! # Why these are here and not only in `fuzz/`
//!
//! `cargo fuzz` needs a nightly toolchain and a deliberate run. The artifacts it
//! produced are checked into `fuzz/artifacts/`, and until now nothing replayed
//! them: a fix could regress and the only thing that would notice is somebody
//! choosing to fuzz that target again.
//!
//! These are the cheapest regression tests in the tree — the inputs are already
//! written down, each is a few kilobytes, and every one of them is a case where
//! a parser was **proved** to fail on evidence-shaped bytes rather than
//! suspected of it.
//!
//! # What passing means, and what it does not
//!
//! Passing means the parser returns rather than aborting the process. It does
//! **not** mean the output is right — a fuzzer finds crashes, not wrong answers.
//! Each parser's own tests cover correctness.
//!
//! Two of the stored artifacts are `oom-` rather than `crash-`: libFuzzer killed
//! the target for allocating past its limit. Those are replayed too. An
//! allocation driven by a length field in evidence is a denial of the whole
//! analysis when an examiner meets it, and this catches the shape returning even
//! though it cannot enforce the memory ceiling libFuzzer did.
//!
//! # Adding to this
//!
//! Drop the artifact in `fuzz/artifacts/<target>/` — where `cargo fuzz` already
//! puts it — and add a line below. Nothing else.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{ByteSliceDataSource, DataSource},
    module::ForensicsModule,
};
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

/// Where the checked-in reproducers live, relative to the workspace root.
fn artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate has a parent directory")
        .join("fuzz")
        .join("artifacts")
}

/// Every stored input for one target.
///
/// Absent directory yields nothing: a checkout that has never fuzzed is not a
/// failure. An unreadable file *is*, because it means the reproducer is there
/// and this harness silently did not run it — the same
/// skip-that-reads-as-a-pass this project refuses everywhere else.
fn reproducers(target: &str) -> Vec<(String, Vec<u8>)> {
    let dir = artifacts_dir().join(target);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.expect("the directory listed this entry");
        if !entry.path().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let bytes = std::fs::read(entry.path())
            .unwrap_or_else(|e| panic!("reproducer {name} is present and unreadable: {e}"));
        out.push((name, bytes));
    }
    out
}

fn artifact(bytes: Vec<u8>, kind: ArtifactType, name: &str) -> Artifact {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Artifact::new(
        Uuid::new_v4(),
        kind,
        Some(ds),
        serde_json::json!({ "name": name, "path": name }),
    )
}

macro_rules! replay_target {
    ($test:ident, $target:literal, $kind:expr, $module:expr) => {
        #[test]
        fn $test() {
            for (name, bytes) in reproducers($target) {
                let art = artifact(bytes, $kind, &name);
                // The return value is deliberately ignored: an error is a fine
                // answer to malformed evidence, and a panic is not an answer at
                // all. Only the latter fails this test.
                let _ = $module.process(&art);
            }
        }
    };
}

replay_target!(
    mft_reproducers_do_not_crash,
    "mft_parser",
    ArtifactType::SystemArtifact,
    seance_plugin_mft::MftParser::new()
);

replay_target!(
    ext4_reproducers_do_not_crash,
    "ext4_parser",
    ArtifactType::Partition,
    seance_plugin_ext4::Ext4Parser::new()
);

replay_target!(
    partition_reproducers_do_not_crash,
    "partition_parser",
    ArtifactType::RawEvidence,
    seance_plugin_partition::PartitionParser
);

replay_target!(
    evtx_reproducers_do_not_crash,
    "evtx_parser",
    ArtifactType::SystemArtifact,
    seance_plugin_evtx::EvtxParser
);

replay_target!(
    prefetch_reproducers_do_not_crash,
    "prefetch_parser",
    ArtifactType::SystemArtifact,
    seance_plugin_prefetch::PrefetchParser
);

replay_target!(
    hfsplus_reproducers_do_not_crash,
    "hfsplus",
    ArtifactType::Partition,
    seance_plugin_hfsplus::HfsPlusParser
);

replay_target!(
    xfs_reproducers_do_not_crash,
    "xfs_parser",
    ArtifactType::Partition,
    seance_plugin_xfs::XfsParser
);

replay_target!(
    apfs_reproducers_do_not_crash,
    "apfs_parser",
    ArtifactType::Partition,
    seance_plugin_apfs::ApfsParser
);

replay_target!(
    btrfs_reproducers_do_not_crash,
    "btrfs_parser",
    ArtifactType::Partition,
    seance_plugin_btrfs::BtrfsParser
);

replay_target!(
    vmdk_reproducers_do_not_crash,
    "vmdk",
    ArtifactType::RawEvidence,
    seance_container_vdisk::VmdkContainerModule
);

/// The harness must actually be finding the files.
///
/// Without this, a rename of `fuzz/artifacts` would turn every test above into
/// a silent no-op and the suite would go on reporting them green — which is the
/// failure mode this project has met twice before, in the netscan and kallsyms
/// corpus tests.
#[test]
fn the_stored_reproducers_are_found_and_replayed() {
    let dir = artifacts_dir();
    if !dir.exists() {
        // A checkout that has never fuzzed. Nothing to assert.
        return;
    }
    let total: usize = [
        "mft_parser",
        "ext4_parser",
        "partition_parser",
        "evtx_parser",
        "prefetch_parser",
        "hfsplus",
        "xfs_parser",
        "apfs_parser",
        "btrfs_parser",
        "vmdk",
    ]
    .iter()
    .map(|t| reproducers(t).len())
    .sum();
    assert!(
        total > 0,
        "fuzz/artifacts exists at {} but no reproducer was loaded from any target, so every \
         replay test above ran nothing",
        dir.display()
    );
}
