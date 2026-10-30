//! Raw carving sweep over the held DFTT and NIST DFR corpora (CARVE-015).
//!
//! Ignored by default: it reads ~72 GB. It runs the raw carving engine, with
//! every registered signature, over each image and writes one line per carve
//! (`image\toffset\tsize\tsignature\tvalidated`) to the file named by
//! `CARVE_SWEEP_OUT`, so two runs can be diffed to measure a signature change:
//!
//! ```text
//! CARVE_SWEEP_OUT=/path/before.tsv \
//!   cargo test --release -p seance_carving --test corpus_sweep -- --ignored --nocapture
//! ```
//!
//! `CARVE_SWEEP_ROOT` overrides the corpus root (default
//! `~/forensic_corpora`); `CARVE_SWEEP_THREADS` the parallelism.

use seance_carving::engine::{CarvingDataSource, CarvingEngine};
use seance_carving::formats;
use seance_carving::SignatureRegistry;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

struct FileSource {
    file: File,
    len: u64,
}

impl CarvingDataSource for FileSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read_at(buf, offset)
    }
    fn size(&self) -> u64 {
        self.len
    }
}

fn images(root: &Path) -> Vec<PathBuf> {
    let mut out = vec![
        root.join("dftt/11-carve-fat/11-carve-fat/11-carve-fat.dd"),
        root.join("dftt/12-carve-ext2/12-carve-ext2/12-carve-ext2.dd"),
    ];
    if let Ok(dir) = std::fs::read_dir(root.join("nist_dfr/dd")) {
        let mut dfr: Vec<PathBuf> = dir
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "dd"))
            .collect();
        dfr.sort();
        out.extend(dfr);
    }
    out.retain(|p| p.is_file());
    out
}

#[test]
#[ignore = "reads the held forensic corpora (~72 GB); run by hand to diff a signature change"]
fn carve_sweep_over_held_corpora() {
    let root = std::env::var_os("CARVE_SWEEP_ROOT").map_or_else(
        || PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join("forensic_corpora"),
        PathBuf::from,
    );
    let out_path = std::env::var("CARVE_SWEEP_OUT").expect("set CARVE_SWEEP_OUT");
    let threads: usize = std::env::var("CARVE_SWEEP_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);

    let mut registry = SignatureRegistry::new();
    formats::register_all(&mut registry);
    let registry = Arc::new(registry);

    let queue = Arc::new(Mutex::new(images(&root)));
    assert!(
        !queue.lock().unwrap().is_empty(),
        "no images under {root:?}"
    );
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));

    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let (queue, lines, registry) = (queue.clone(), lines.clone(), registry.clone());
            std::thread::spawn(move || loop {
                let Some(path) = queue.lock().unwrap().pop() else {
                    break;
                };
                let file = File::open(&path).expect("open image");
                let len = file.metadata().expect("stat image").len();
                let source = FileSource { file, len };
                let engine = CarvingEngine::new(registry.clone());
                let found = engine.scan(&source, len);
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                eprintln!("{name}: {} carves", found.len());
                let mut l = lines.lock().unwrap();
                for f in found {
                    l.push(format!(
                        "{name}\t{}\t{}\t{}\t{:?}",
                        f.offset, f.size, f.signature_name, f.validated
                    ));
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("sweep thread");
    }

    let mut lines = Arc::try_unwrap(lines).unwrap().into_inner().unwrap();
    lines.sort();
    let mut out = File::create(&out_path).expect("create output");
    for l in &lines {
        writeln!(out, "{l}").unwrap();
    }
    eprintln!("{} carves written to {out_path}", lines.len());
}
