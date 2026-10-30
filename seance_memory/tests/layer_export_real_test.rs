//! The layer export ([`seance_memory::export`]) against a real acquisition.
//!
//! `win10.dmp` is the corpus's genuine Windows 11 26200 kernel crash dump (see
//! `real_image_test.rs`): 383 MiB of stored pages that reconstruct a 10 GiB
//! sparse physical space through the dump's run table. It is the right test of
//! a hole manifest because its holes are not ours: the dump's own run table
//! says which physical ranges were saved, and the manifest has to say exactly
//! the complement.
//!
//! Nothing is written to disk. The export streams into a sink that counts the
//! bytes, checks that every byte the manifest calls fill is fill, and keeps the
//! bytes at a handful of sampled addresses to compare with the crash reader's
//! own reads.
//!
//! Runs only when `SEANCE_MEM_IMAGES` names the corpus directory; skips and
//! says so otherwise, and fails if the corpus is named but the file is missing.

use std::io::{self, Write};
use std::sync::Arc;

use seance_core::data_source::{DataSource, FileDataSource};
use seance_memory::export::{plan_export, write_export, ExportPlan, FILL_BYTE};
use seance_memory::{formats, open_physical_layer, MemoryImageFormat};

fn open_file(name: &str) -> Option<Arc<dyn DataSource>> {
    let path = seance_core::test_support::corpus::file("SEANCE_MEM_IMAGES", name)?;
    Some(Arc::new(FileDataSource::new(path).expect("open image")) as Arc<dyn DataSource>)
}

/// Counts, checks fill, and keeps sampled bytes.
struct CheckingSink<'a> {
    at: u64,
    plan: &'a ExportPlan,
    samples: Vec<(u64, Vec<u8>)>,
    fill_violations: u64,
}

impl Write for CheckingSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let from = self.at;
        let to = from + buf.len() as u64;
        for hole in &self.plan.holes {
            let hs = hole.start - self.plan.start;
            let he = hs + hole.length;
            let (a, b) = (hs.max(from), he.min(to));
            if a < b {
                let slice = &buf[(a - from) as usize..(b - from) as usize];
                self.fill_violations += slice.iter().filter(|x| **x != FILL_BYTE).count() as u64;
            }
        }
        for (addr, keep) in &mut self.samples {
            let off = *addr - self.plan.start;
            if off >= from && off < to && keep.is_empty() {
                let end = (off + 64).min(to);
                keep.extend_from_slice(&buf[(off - from) as usize..(end - from) as usize]);
            }
        }
        self.at = to;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn win10_crash_dump_exports_with_the_run_table_complement_as_its_holes() {
    let Some(src) = open_file("win10.dmp") else {
        return;
    };

    let dump = formats::crash::open(Arc::clone(&src)).expect("decode the crash dump");
    let mut backed: Vec<(u64, u64)> = Vec::new();
    for seg in dump.segments() {
        match backed.last_mut() {
            Some((s, l)) if *s + *l == seg.memory_offset => *l += seg.length,
            _ => backed.push((seg.memory_offset, seg.length)),
        }
    }

    let layer = open_physical_layer(MemoryImageFormat::WindowsCrashDump64, &src)
        .expect("the export seam decodes the dump");
    let plan = plan_export(layer.as_ref(), 0, None).expect("plans");

    // The manifest is exactly the complement of the dump's run table.
    let mut expected_holes = Vec::new();
    let mut pos = 0u64;
    for (s, l) in &backed {
        if *s > pos {
            expected_holes.push((pos, *s - pos));
        }
        pos = s + l;
    }
    if pos < plan.end {
        expected_holes.push((pos, plan.end - pos));
    }
    let got: Vec<(u64, u64)> = plan.holes.iter().map(|h| (h.start, h.length)).collect();
    assert_eq!(
        got, expected_holes,
        "holes must be the run table's complement"
    );
    assert_eq!(
        plan.backed_bytes(),
        dump.mapped_len(),
        "backed bytes must equal the bytes the dump stores"
    );

    // Sample the first 64 bytes of the first, middle and last runs.
    let picks = [0, backed.len() / 2, backed.len() - 1];
    let mut sink = CheckingSink {
        at: 0,
        plan: &plan,
        samples: picks.iter().map(|i| (backed[*i].0, Vec::new())).collect(),
        fill_violations: 0,
    };
    let written = write_export(layer.as_ref(), &plan, &mut sink).expect("streams");
    assert_eq!(written, plan.total_bytes());
    assert_eq!(sink.at, plan.total_bytes());
    assert_eq!(sink.fill_violations, 0, "every hole byte is fill");
    for (addr, bytes) in &sink.samples {
        let mut direct = vec![0u8; bytes.len()];
        dump.read_at(*addr, &mut direct)
            .expect("read through the dump");
        assert_eq!(bytes, &direct, "exported bytes at {addr:#x} are the dump's");
    }

    eprintln!(
        "win10.dmp export: {} bytes, {} backed, {} fill in {} holes",
        plan.total_bytes(),
        plan.backed_bytes(),
        plan.hole_bytes(),
        plan.holes.len()
    );
}
