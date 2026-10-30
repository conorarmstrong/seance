//! Random-access backing store for a decompressed stream.
//!
//! gzip/bzip2/xz are stream formats: to let a downstream extractor (tar) window
//! into an entry, the decompressed bytes must be randomly addressable. Holding a
//! multi-GB device dump in memory is not an option, so we spill the decompressed
//! stream to an anonymous temp file and expose it as a [`DataSource`]. The file
//! is unlinked on creation (Unix) / delete-on-close (Windows) and vanishes when
//! the last [`Arc`](std::sync::Arc) referencing this source drops — the tar entry
//! [`WindowSource`](seance_core::data_source::WindowSource)s keep it alive for
//! exactly as long as they are being read.

use seance_core::data_source::DataSource;
use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::Mutex;

#[cfg(not(unix))]
use std::io::{Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::FileExt;

/// A [`DataSource`] backed by an anonymous temp file that is removed once the
/// last reference drops.
#[derive(Debug)]
pub struct TempBackedSource {
    file: Mutex<File>,
    size: u64,
}

impl TempBackedSource {
    /// Stream `reader` into a fresh temp file, up to `cap` bytes, and expose the
    /// result as a random-access source. `cap` is the caller's decompression-bomb
    /// limit; a stream that would exceed it fails closed.
    ///
    /// A decode error at *any* point fails closed. Unlike a multi-file tar (where
    /// already-parsed entries stay valid), gzip/bzip2/xz decode a single stream:
    /// a mid-stream error means the decompressed payload is truncated, and
    /// returning the partial temp file would serve truncated content as a complete
    /// stream (wrong hashes, silent incompleteness). The caller skips the artifact
    /// rather than ingest a partial as whole.
    pub fn from_reader<R: Read>(reader: R, cap: u64) -> io::Result<Self> {
        let mut file = tempfile::tempfile()?;
        // Read one byte past the cap so a stream that would exceed it is detected
        // and fails closed, instead of being silently truncated at the cap and
        // served as a complete decompressed image.
        let mut limited = reader.take(cap.saturating_add(1));
        let mut buf = [0u8; 64 * 1024];
        let mut written: u64 = 0;
        loop {
            match limited.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if written + n as u64 > cap {
                        return Err(crate::limits::cap_exceeded(cap));
                    }
                    file.write_all(&buf[..n])?;
                    written += n as u64;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    // A mid-stream decode error truncates the payload. Never keep
                    // the partial temp file as a complete stream; fail closed.
                    return Err(io::Error::new(
                        e.kind(),
                        format!(
                            "decompression failed after {written} bytes; \
                             refusing to serve a truncated stream as complete: {e}"
                        ),
                    ));
                }
            }
        }
        file.flush()?;
        Ok(Self {
            file: Mutex::new(file),
            size: written,
        })
    }
}

impl DataSource for TempBackedSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            let file = self
                .file
                .lock()
                .map_err(|_| io::Error::other("Mutex poisoned"))?;
            file.read_at(buf, offset)
        }

        #[cfg(not(unix))]
        {
            let mut file = self
                .file
                .lock()
                .map_err(|_| io::Error::other("Mutex poisoned"))?;
            file.seek(SeekFrom::Start(offset))?;
            file.read(buf)
        }
    }

    fn size(&self) -> u64 {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materializes_and_reads_back() {
        let data = vec![7u8; 200_000]; // larger than the internal 64 KiB buffer
        let src = TempBackedSource::from_reader(&data[..], u64::MAX).unwrap();
        assert_eq!(src.size(), 200_000);
        let mut buf = [0u8; 100];
        let n = src.read_at(199_950, &mut buf).unwrap();
        assert_eq!(n, 50);
        assert!(buf[..50].iter().all(|&b| b == 7));
    }

    #[test]
    fn cap_exceeded_fails_closed() {
        // BUG-051: a decompressed stream larger than the cap must fail closed,
        // not be silently truncated at the cap and served as a complete image.
        let data = vec![0u8; 10_000];
        let err = TempBackedSource::from_reader(&data[..], 4096).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn stream_exactly_at_cap_succeeds() {
        // A stream whose length equals the cap is complete, not truncated.
        let data = vec![0u8; 4096];
        let src = TempBackedSource::from_reader(&data[..], 4096).unwrap();
        assert_eq!(src.size(), 4096);
    }

    #[test]
    fn read_past_end_returns_zero() {
        let src = TempBackedSource::from_reader(&b"abc"[..], u64::MAX).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(src.read_at(10, &mut buf).unwrap(), 0);
    }

    #[test]
    fn error_before_output_propagates() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("boom"))
            }
        }
        assert!(TempBackedSource::from_reader(FailingReader, u64::MAX).is_err());
    }

    #[test]
    fn mid_stream_error_after_output_fails_closed() {
        // BUG-095: a decode error *after* some output must fail closed, not return
        // the partial bytes as a complete (truncated-as-whole) stream.
        struct PartialThenFail {
            emitted: bool,
        }
        impl Read for PartialThenFail {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.emitted {
                    self.emitted = true;
                    let n = buf.len().min(4);
                    buf[..n].fill(0x41);
                    Ok(n)
                } else {
                    Err(io::Error::other("mid-stream corruption"))
                }
            }
        }
        let err = TempBackedSource::from_reader(PartialThenFail { emitted: false }, u64::MAX)
            .unwrap_err();
        assert!(
            err.to_string().contains("truncated"),
            "expected a truncation error, got: {err}"
        );
    }
}
