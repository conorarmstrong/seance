use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::FileDataSource,
    module::ForensicsModule,
};
use seance_plugin_ext4::Ext4Parser;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

/// Resolve a fixture relative to the workspace root. Benches run with CWD set to
/// the crate dir, but the fixtures live at the workspace-root `test_data/`.
fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
}

fn benchmark_ext4_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ext4_parsing");

    // Test files with different sizes
    let test_files = vec![("small_4mb", "test_data/ext4.raw")];

    for (name, rel) in test_files {
        let path = fixture(rel);
        if !path.exists() {
            eprintln!("Skipping benchmark {}: {} not found", name, path.display());
            continue;
        }

        group.bench_with_input(BenchmarkId::new("parse", name), &path, |b, path| {
            let plugin = Ext4Parser::new();
            let case_id = Uuid::new_v4();

            b.iter(|| {
                // Create data source from file
                let data_source = Arc::new(FileDataSource::new(path.clone()).unwrap());

                // Create artifact with Ext4 data source
                let artifact = Artifact::new(
                    case_id,
                    ArtifactType::FileSystem,
                    Some(data_source),
                    json!({ "name": path.display().to_string(), "filesystem": "ext4" }),
                );

                // Parse Ext4
                let result = plugin.process(black_box(&artifact));

                // Ensure we actually parsed something
                assert!(result.is_ok());
                let artifacts = result.unwrap();
                assert!(!artifacts.is_empty(), "Ext4 parsing produced no artifacts");
            });
        });
    }

    group.finish();
}

fn benchmark_ext4_superblock(c: &mut Criterion) {
    let mut group = c.benchmark_group("ext4_superblock");

    let path = fixture("test_data/ext4.raw");

    if path.exists() {
        group.throughput(criterion::Throughput::Elements(1));

        group.bench_function("read_superblock", |b| {
            let plugin = Ext4Parser::new();
            let case_id = Uuid::new_v4();

            b.iter(|| {
                let data_source = Arc::new(FileDataSource::new(path.clone()).unwrap());

                let artifact = Artifact::new(
                    case_id,
                    ArtifactType::FileSystem,
                    Some(data_source),
                    json!({ "name": path.display().to_string(), "filesystem": "ext4" }),
                );

                // Parse just the superblock (this happens on first access)
                let result = plugin.process(black_box(&artifact));
                assert!(result.is_ok());
            });
        });
    } else {
        eprintln!(
            "Skipping superblock benchmark: {} not found",
            path.display()
        );
    }

    group.finish();
}

fn benchmark_ext4_directory_traversal(c: &mut Criterion) {
    let mut group = c.benchmark_group("ext4_directory_traversal");

    let path = fixture("test_data/ext4.raw");

    if path.exists() {
        group.bench_function("traverse_all", |b| {
            let plugin = Ext4Parser::new();
            let case_id = Uuid::new_v4();

            b.iter(|| {
                let data_source = Arc::new(FileDataSource::new(path.clone()).unwrap());

                let artifact = Artifact::new(
                    case_id,
                    ArtifactType::FileSystem,
                    Some(data_source),
                    json!({ "name": path.display().to_string(), "filesystem": "ext4" }),
                );

                // Full traversal includes all directories and files
                let result = plugin.process(black_box(&artifact));
                assert!(result.is_ok());
                let artifacts = result.unwrap();

                // Count directory entries
                let _count = artifacts.len();
            });
        });
    } else {
        eprintln!(
            "Skipping directory traversal benchmark: {} not found",
            path.display()
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_ext4_parsing,
    benchmark_ext4_superblock,
    benchmark_ext4_directory_traversal
);
criterion_main!(benches);
