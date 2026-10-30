# Seance Performance Benchmarks

This package contains performance benchmarks for critical paths in the Seance forensics framework using the Criterion benchmarking library.

## Read this first

**Two things will make these benchmarks measure nothing, silently.**

1. **The E01 bench is behind a cargo feature.** `seance_container_e01` is an
   optional dependency and `[[bench]] name = "e01_parsing"` carries
   `required-features = ["e01"]`, so it is off by default — the crate builds
   without libewf. Without `--features e01` the bench is simply not built, and
   the run says nothing about E01 performance.
2. **Every bench skips a missing fixture with a message on stderr and no
   failure.** A run over an empty `test_data/` prints a handful of
   `Skipping benchmark …: not found` lines and reports success. Read the stderr,
   not the exit code.

> **The MFT fixtures sit at the workspace root.**
> `benches/mft_parsing.rs` resolves `test_data/compressed_sparse.mft` and
> `test_data/4k-large.mft` at the **workspace root**. `test_data/mft/` is where
> `seance_plugin_mft`'s tests and `seance_tests` look for their *other* MFT
> fixtures (`nist-hacking-case.mft`, the `*.golden.jsonl` goldens). Provision
> the benchmark files under `test_data/mft/` and both MFT benchmarks skip.
> `test_data/README.md` warns about the same split.

- **parse/small_256kb** - Parse 256KB MFT file (`test_data/compressed_sparse.mft` — **root**, see the warning above)
- **parse/medium_1mb** - Parse 1MB MFT file (`test_data/4k-large.mft` — **root**)
- **single_record** - Measures per-record parsing throughput (`test_data/4k-large.mft`)

**Targets that are NOT measured here** (see *Performance Targets* below):
- 100k records: < 30 seconds
- 500k records: < 2 minutes
- 1M records: < 5 minutes

### Ext4 Parsing (`ext4_parsing`)

Tests Ext4 filesystem parsing performance:

- **parse/small_4mb** - Parse 4MB Ext4 image (`test_data/ext4.raw`)
- **read_superblock** - Measures superblock reading performance
- **traverse_all** - Full directory tree traversal and file enumeration

**Targets that are NOT measured here** (see *Performance Targets* below):
- 10k files directory: Fast traversal
- 100k files htree directory: Efficient handling

### E01 Container (`e01_parsing`)

Tests E01 forensic image container operations:

- **open/single_segment** - Open single-segment E01 (`test_data/image.E01`)
- **open/multi_segment** - Open multi-segment E01 (`test_data/image-split.E01`)
- **sequential_read/chunk_size/N** - Sequential reads with various chunk sizes (1KB, 4KB, 64KB, 1MB)
- **4kb_random** - Random 4KB reads across image
- **open_and_read** - Full open + multi-position read workflow

**Targets that are NOT measured here** (see *Performance Targets* below):
- 100GB E01 image: Efficient access
- 1TB raw image: Good performance
- 2TB+ image: WindowSource optimization validated

## Test Data Requirements

Benchmarks will skip gracefully if test data files are missing. See `test_data/README.md` for information about:
- Where to obtain test files
- File formats and sizes
- Data privacy guidelines

Required test files, at the paths the benches actually resolve:

| Path (relative to the **workspace root**) | Bench |
|---|---|
| `test_data/compressed_sparse.mft` (256KB) | `mft_parsing/parse/small_256kb` |
| `test_data/4k-large.mft` (1MB) | `mft_parsing/parse/medium_1mb`, `single_record` |
| `test_data/ext4.raw` (4MB) | all three `ext4_parsing` groups |
| `test_data/image.E01` | `e01_parsing` open / sequential / random / open_and_read |
| `test_data/image-split.E01` + `.E02` | `e01_parsing/open/multi_segment` |

None of these is in the repository — `/test_data/` is gitignored. See
`test_data/README.md`, which is the file that says how to obtain or build each
sample.

## Interpreting Results

Criterion generates detailed reports in `target/criterion/`:

```
target/criterion/
├── mft_parsing/
│   ├── parse/
│   │   ├── small_256kb/
│   │   └── medium_1mb/
│   └── single_record/
├── ext4_parsing/
└── e01_parsing/
```

Each benchmark directory contains:
- `report/index.html` - Interactive HTML report with charts
- `base/` - Baseline measurements for comparison
- `new/` - Latest run measurements

### Reading Benchmark Output

Example output:
```
mft_parsing/parse/small_256kb
                        time:   [12.345 ms 12.456 ms 12.567 ms]
                        change: [-2.3% +0.5% +3.2%] (p = 0.23 > 0.05)
                        No change in performance detected.
```

- **time:** Mean execution time with confidence interval
- **change:** Performance delta from previous run (regression/improvement)
- **p-value:** Statistical significance (< 0.05 = significant change)

### Performance Regression Detection

Criterion automatically detects performance regressions:
- **Red/increased**: Performance degraded (slower)
- **Green/decreased**: Performance improved (faster)
- **No change**: Within noise threshold

## Continuous Integration

**No CI job runs these benchmarks.** Nothing in `.github/workflows/` invokes
`cargo bench`, so a performance regression is caught when somebody runs them by
hand and not before. The commands below are how it *would* be wired, not a description of
something that runs:

```bash
# Save baseline
cargo bench --package seance_benchmarks --features e01 -- --save-baseline main

# Compare against baseline
cargo bench --package seance_benchmarks --features e01 -- --baseline main
```

Criterion reports a regression in its output; it does not fail the process on
one. A CI gate would have to read the comparison and decide, which is the part
that is not built.

## Performance Targets — **aspirations, not measurements**

Every one of them needs larger test data than is held. No benchmark in
this crate measures any of them: the largest fixture any bench opens is 4 MB.
They are stated here so the gap between what is measured and what was hoped for
is visible, and they must not be quoted as results.

| Component | Dataset Size | Target Time | Measured here? |
|-----------|-------------|-------------|---|
| MFT Parser | 100k records | < 30 seconds | ❌ |
| MFT Parser | 500k records | < 2 minutes | ❌ |
| MFT Parser | 1M records | < 5 minutes | ❌ |
| E01 Container | 100GB image | Efficient access | ❌ |
| E01 Container | 1TB image | Good performance | ❌ |
| E01 Container | 2TB+ (`WindowSource`) | Validated | ❌ |
| Ext4 Parser | 10k-file directory | Fast traversal | ❌ |
| Ext4 Parser | 100k files (htree) | Efficient handling | ❌ |

**What *is* measured:** MFT parsing of a 256 KB and a 1 MB file plus per-record
throughput; ext4 superblock read, whole-image parse and full tree traversal on a
4 MB image; E01 open (single- and multi-segment), sequential reads at 1 KB / 4 KB
/ 64 KB / 1 MB chunk sizes, random 4 KB reads, and a combined open-and-read
workflow. Those are the numbers this crate can defend.

## Adding New Benchmarks

1. Create benchmark file in `benches/` directory:
   ```rust
   use criterion::{black_box, criterion_group, criterion_main, Criterion};

   fn benchmark_name(c: &mut Criterion) {
       c.bench_function("my_benchmark", |b| {
           b.iter(|| {
               // Code to benchmark
               black_box(expensive_operation());
           });
       });
   }

   criterion_group!(benches, benchmark_name);
   criterion_main!(benches);
   ```

2. Add benchmark to `Cargo.toml`:
   ```toml
   [[bench]]
   name = "my_benchmark"
   harness = false
   ```

3. Add dependencies if needed to `[dependencies]` section. If the dependency
   is optional, give the bench `required-features` so it is skipped rather than
   failing to build — and **say so at the top of this file**, because a bench
   that is silently not built is indistinguishable from one that found nothing.

4. Document what the benchmark measures. Do not add a target it does not
   measure to the *Performance Targets* table without marking it ❌.

## Resources

- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/book/)
- [Criterion.rs User Guide](https://bheisler.github.io/criterion.rs/book/user_guide/user_guide.html)
- Seance testing strategy (maintained): `documentation/TESTING.md`
