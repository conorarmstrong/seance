use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::FileDataSource,
    module::ForensicsModule,
};
use seance_plugin_mft::MftParser;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

/// Resolve a fixture relative to the workspace root. Benches run with CWD set to
/// the crate dir, but the fixtures live at the workspace-root `test_data/`.
fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
}

fn benchmark_mft_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("mft_parsing");

    // Test files with different sizes
    let test_files = vec![
        ("small_256kb", "test_data/compressed_sparse.mft"),
        ("medium_1mb", "test_data/4k-large.mft"),
    ];

    for (name, rel) in test_files {
        let path = fixture(rel);
        if !path.exists() {
            eprintln!("Skipping benchmark {}: {} not found", name, path.display());
            continue;
        }

        group.bench_with_input(BenchmarkId::new("parse", name), &path, |b, path| {
            let plugin = MftParser::new();
            let case_id = Uuid::new_v4();

            b.iter(|| {
                // Create data source from file
                let data_source = Arc::new(FileDataSource::new(path.clone()).unwrap());

                // Create artifact with MFT data source
                let artifact = Artifact::new(
                    case_id,
                    ArtifactType::SystemArtifact,
                    Some(data_source),
                    json!({ "name": path.display().to_string() }),
                );

                // Parse MFT
                let result = plugin.process(black_box(&artifact));

                // Ensure we actually parsed something
                assert!(result.is_ok());
                let artifacts = result.unwrap();
                assert!(!artifacts.is_empty(), "MFT parsing produced no artifacts");
            });
        });
    }

    group.finish();
}

fn benchmark_mft_record_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("mft_record_parsing");

    // Benchmark individual record parsing throughput
    let path = fixture("test_data/4k-large.mft");

    if path.exists() {
        group.throughput(criterion::Throughput::Elements(1));

        group.bench_function("single_record", |b| {
            let plugin = MftParser::new();
            let case_id = Uuid::new_v4();
            let data_source = Arc::new(FileDataSource::new(path.clone()).unwrap());

            let artifact = Artifact::new(
                case_id,
                ArtifactType::SystemArtifact,
                Some(data_source),
                json!({ "name": path.display().to_string() }),
            );

            b.iter(|| {
                let result = plugin.process(black_box(&artifact));
                assert!(result.is_ok());
            });
        });
    } else {
        eprintln!(
            "Skipping single_record benchmark: {} not found",
            path.display()
        );
    }

    group.finish();
}

criterion_group!(benches, benchmark_mft_parsing, benchmark_mft_record_parsing);
criterion_main!(benches);
