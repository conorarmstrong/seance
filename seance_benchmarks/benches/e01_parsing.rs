use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use seance_container_e01::E01DataSource;
use seance_core::data_source::DataSource;
use std::path::{Path, PathBuf};

/// Resolve a fixture relative to the workspace root. Benches run with CWD set to
/// the crate dir, but the fixtures live at the workspace-root `test_data/`.
fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
}

fn benchmark_e01_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("e01_open");

    let test_files = vec![
        ("single_segment", "test_data/image.E01"),
        ("multi_segment", "test_data/image-split.E01"),
    ];

    for (name, rel) in test_files {
        let path = fixture(rel);
        if !path.exists() {
            eprintln!("Skipping benchmark {}: {} not found", name, path.display());
            continue;
        }

        group.bench_with_input(BenchmarkId::new("open", name), &path, |b, path| {
            let path = path.to_str().unwrap();
            b.iter(|| {
                let result = E01DataSource::open(black_box(path));
                assert!(result.is_ok(), "Failed to open E01: {:?}", result.err());
            });
        });
    }

    group.finish();
}

fn benchmark_e01_sequential_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("e01_sequential_read");

    let path = fixture("test_data/image.E01");

    if path.exists() {
        let source = E01DataSource::open(path.to_str().unwrap()).expect("Failed to open E01");
        let _total_size = source.size();

        // Benchmark reading 1KB, 4KB, 64KB, 1MB chunks
        for chunk_size in [1024, 4096, 65536, 1024 * 1024] {
            group.throughput(Throughput::Bytes(chunk_size as u64));

            group.bench_with_input(
                BenchmarkId::new("chunk_size", chunk_size),
                &chunk_size,
                |b, &size| {
                    let mut buffer = vec![0u8; size];

                    b.iter(|| {
                        // Read from offset 0
                        let bytes_read = source
                            .read_at(black_box(0), black_box(&mut buffer))
                            .unwrap();
                        assert!(bytes_read > 0, "Read returned 0 bytes");
                    });
                },
            );
        }
    } else {
        eprintln!(
            "Skipping sequential read benchmark: {} not found",
            path.display()
        );
    }

    group.finish();
}

fn benchmark_e01_random_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("e01_random_read");

    let path = fixture("test_data/image.E01");

    if path.exists() {
        let source = E01DataSource::open(path.to_str().unwrap()).expect("Failed to open E01");
        let total_size = source.size();

        if total_size > 0 {
            let chunk_size = 4096;
            group.throughput(Throughput::Bytes(chunk_size as u64));

            group.bench_function("4kb_random", |b| {
                let mut buffer = vec![0u8; chunk_size];
                let mut offset = 0u64;

                b.iter(|| {
                    // Read at incrementing offsets (pseudo-random pattern)
                    offset = (offset + 65536) % total_size;

                    let bytes_read = source
                        .read_at(black_box(offset), black_box(&mut buffer))
                        .unwrap();
                    assert!(
                        bytes_read > 0 || offset >= total_size,
                        "Read failed at offset {}",
                        offset
                    );
                });
            });
        }
    } else {
        eprintln!(
            "Skipping random read benchmark: {} not found",
            path.display()
        );
    }

    group.finish();
}

fn benchmark_e01_multi_segment(c: &mut Criterion) {
    let mut group = c.benchmark_group("e01_multi_segment");

    let path = fixture("test_data/image-split.E01");

    if path.exists() {
        let path = path.to_str().unwrap().to_string();
        group.bench_function("open_and_read", |b| {
            b.iter(|| {
                let source =
                    E01DataSource::open(black_box(path.as_str())).expect("Failed to open E01");
                let total_size = source.size();

                // Read from multiple positions across segments
                let mut buffer = vec![0u8; 4096];

                // Read from start
                let _ = source.read_at(0, &mut buffer);

                // Read from middle (should be in second segment)
                if total_size > 1024 * 1024 {
                    let _ = source.read_at(total_size / 2, &mut buffer);
                }

                // Read from near end
                if total_size > 8192 {
                    let _ = source.read_at(total_size - 4096, &mut buffer);
                }
            });
        });
    } else {
        eprintln!(
            "Skipping multi-segment benchmark: {} not found",
            path.display()
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_e01_open,
    benchmark_e01_sequential_read,
    benchmark_e01_random_read,
    benchmark_e01_multi_segment
);
criterion_main!(benches);
