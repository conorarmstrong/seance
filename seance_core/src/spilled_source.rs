//! A [`DataSource`] whose bytes live in a temporary file, not in memory.
//!
//! A parser that reconstructs a file's content at ingest — an NTFS LZNT1
//! stream inflated out of its compression units — used to hand the whole
//! result on as a [`ByteSliceDataSource`]. Every such artifact the parser had
//! produced stayed resident until the parser returned, and then again for as
//! long as it waited in the task queue, so the bytes held were the sum of every
//! compressed file on the volume: 3.9 GB after 147,712 records of one real
//! Windows 10 disk, in a process that was OOM-killed at ~27 GB on a 33 GB image
//! (HUNT-125).
//!
//! [`spill_or_hold`] keeps small content in memory, where a file would cost
//! more than it saves, and puts anything larger in a [`TempSpill`] that removes
//! itself when the last reference to the source drops. It holds **no open
//! descriptor**: a tree of tens of thousands of these would otherwise run past
//! `ulimit -n` (HUNT-114), so the file is opened for each read.
//!
//! Where the file goes is [`std::env::temp_dir`], so `TMPDIR` decides. On a host
//! whose `/tmp` is a RAM-backed `tmpfs` that is still memory, just not this
//! process's: point `TMPDIR` at a real filesystem for a large ingest
//! (`documentation/DEPLOYMENT.md`).

use std::fs::File;
use std::io;
use std::sync::Arc;

use crate::data_source::{ByteSliceDataSource, DataSource};
use crate::temp_spill::TempSpill;

/// Content below this many bytes stays in memory. A file per artifact is not
/// free, and most reconstructed content is small; the bound on what is held
/// resident is this figure times the artifacts in flight.
pub const SPILL_THRESHOLD_BYTES: usize = 16 * 1024;

/// Bytes held in a temporary file, read back on demand. See the module docs.
#[derive(Debug)]
pub struct SpilledBytesSource {
    spill: TempSpill,
    size: u64,
}

impl SpilledBytesSource {
    /// Write `bytes` to a new temporary file. The file is removed when the
    /// returned source drops.
    pub fn new(bytes: &[u8]) -> io::Result<Self> {
        let spill = TempSpill::write(bytes, "content", "bin")?;
        Ok(Self {
            spill,
            size: bytes.len() as u64,
        })
    }
}

impl DataSource for SpilledBytesSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let file = File::open(self.spill.path())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            file.read_at(buf, offset)
        }
        #[cfg(not(unix))]
        {
            use std::io::{Read, Seek, SeekFrom};
            let mut file = file;
            file.seek(SeekFrom::Start(offset))?;
            file.read(buf)
        }
    }

    fn size(&self) -> u64 {
        self.size
    }
    // No `get_underlying_path`, no siblings, no ancestors: the file is an
    // implementation detail and is not a place in the evidence. physical_map
    // keeps the default (opaque), as it does for any reconstructed content.
}

/// Hold `data` as a data source without keeping a large buffer resident.
///
/// Content under [`SPILL_THRESHOLD_BYTES`], or content whose temporary file
/// cannot be written (a full disk, an unwritable `TMPDIR`), stays in memory:
/// the artifact must not lose its content because the spill failed, and the
/// cost of that fallback is the memory it always cost.
pub fn spill_or_hold(data: Vec<u8>) -> Arc<dyn DataSource> {
    if data.len() >= SPILL_THRESHOLD_BYTES {
        match SpilledBytesSource::new(&data) {
            Ok(source) => return Arc::new(source),
            Err(e) => tracing::warn!(
                "could not spill {} bytes of reconstructed content to disk ({}); \
                 holding it in memory",
                data.len(),
                e
            ),
        }
    }
    Arc::new(ByteSliceDataSource::new(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn read_all(src: &dyn DataSource) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 4096];
        let mut off = 0u64;
        loop {
            let n = src.read_at(off, &mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
            off += n as u64;
        }
        out
    }

    #[test]
    fn a_spilled_source_reads_back_what_was_written() {
        let data = pattern(100_000);
        let src = SpilledBytesSource::new(&data).unwrap();
        assert_eq!(src.size(), 100_000);
        assert_eq!(read_all(&src), data);
        // A read in the middle and one that straddles the end.
        let mut buf = [0u8; 10];
        assert_eq!(src.read_at(50_000, &mut buf).unwrap(), 10);
        assert_eq!(&buf[..], &data[50_000..50_010]);
        assert_eq!(src.read_at(99_995, &mut buf).unwrap(), 5);
        assert_eq!(src.read_at(100_000, &mut buf).unwrap(), 0);
    }

    #[test]
    fn a_spilled_source_removes_its_file_and_holds_no_descriptor() {
        let src = SpilledBytesSource::new(&pattern(32 * 1024)).unwrap();
        let path = src.spill.path().to_path_buf();
        assert!(path.exists());
        // No descriptor is open on it: count this process's fds pointing there.
        #[cfg(target_os = "linux")]
        {
            let open_on_it = std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .flatten()
                .filter_map(|e| std::fs::read_link(e.path()).ok())
                .filter(|t| *t == path)
                .count();
            assert_eq!(open_on_it, 0, "a spilled source must not hold a descriptor");
        }
        drop(src);
        assert!(!path.exists(), "the file goes when the source does");
    }

    #[test]
    fn small_content_stays_in_memory_and_large_content_does_not() {
        let small = spill_or_hold(pattern(SPILL_THRESHOLD_BYTES - 1));
        assert!(
            small.resident_bytes().is_some(),
            "under the threshold the bytes stay resident"
        );
        let large = spill_or_hold(pattern(SPILL_THRESHOLD_BYTES));
        assert!(
            large.resident_bytes().is_none(),
            "at the threshold the bytes are on disk"
        );
        assert_eq!(read_all(large.as_ref()), pattern(SPILL_THRESHOLD_BYTES));
        assert!(large.get_underlying_path().is_none());
    }
}
