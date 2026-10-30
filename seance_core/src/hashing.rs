use digest::Digest;
use std::io::Read;

/// Result of computing MD5, SHA1, and SHA256 hashes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashResult {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// Compute MD5, SHA1, and SHA256 in a single pass over in-memory data
pub fn compute_hashes(data: &[u8]) -> HashResult {
    let mut md5 = md5::Md5::new();
    let mut sha1 = sha1::Sha1::new();
    let mut sha256 = sha2::Sha256::new();

    md5.update(data);
    sha1.update(data);
    sha256.update(data);

    HashResult {
        md5: format!("{:x}", md5.finalize()),
        sha1: format!("{:x}", sha1.finalize()),
        sha256: format!("{:x}", sha256.finalize()),
    }
}

/// Compute MD5, SHA1, and SHA256 by streaming from a reader (for large files)
pub fn compute_hashes_streaming<R: Read + Send>(
    reader: &mut R,
    buf_size: usize,
) -> std::io::Result<HashResult> {
    compute_hashes_streaming_with_progress(reader, buf_size, |_| {})
}

/// Like [`compute_hashes_streaming`], reporting bytes hashed via `progress`.
///
/// The callback receives the cumulative byte count. It is rate-limited to at
/// most one call per second, plus a final call with the total once the reader
/// is exhausted.
///
/// # Pipelined read and hash
///
/// The read and the digest run on separate threads, so the disk fills the next
/// chunk while this thread hashes the current one — on evidence where the read
/// and the hash take comparable time (the common case), wall-time drops from
/// `read + hash` per chunk to roughly `max(read, hash)`. Two buffers are
/// ping-ponged between the reader thread and the hashing thread through a pair
/// of channels; nothing is allocated per chunk after the initial two.
///
/// The output is byte-identical to a single in-memory pass: the reader thread
/// preserves chunk order, and each digest still sees the same bytes in the same
/// order. A read error is delivered in-band and returned from here unchanged.
pub fn compute_hashes_streaming_with_progress<R: Read + Send, F: FnMut(u64)>(
    reader: &mut R,
    buf_size: usize,
    mut progress: F,
) -> std::io::Result<HashResult> {
    use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

    // A filled buffer and how many bytes of it are live, or a read error.
    type Filled = std::io::Result<(Vec<u8>, usize)>;

    // `filled`: reader -> hasher (bounded to one, so the reader runs at most one
    // chunk ahead). `free`: hasher -> reader, recycling the two buffers.
    let (filled_tx, filled_rx): (SyncSender<Filled>, Receiver<Filled>) = sync_channel(1);
    let (free_tx, free_rx): (SyncSender<Vec<u8>>, Receiver<Vec<u8>>) = sync_channel(2);
    // Seed the two buffers the reader will fill.
    let buf_size = buf_size.max(1);
    free_tx
        .send(vec![0u8; buf_size])
        .expect("hasher end is live");
    free_tx
        .send(vec![0u8; buf_size])
        .expect("hasher end is live");

    std::thread::scope(|scope| -> std::io::Result<HashResult> {
        // Reader thread: pull a free buffer, fill it, hand it to the hasher.
        // Stops when the stream ends, on a read error, or when the hasher has
        // gone (its channels drop, so recv/send here fail and we break).
        scope.spawn(move || {
            while let Ok(mut buf) = free_rx.recv() {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        let _ = filled_tx.send(Ok((buf, 0)));
                        break;
                    }
                    Ok(n) => {
                        if filled_tx.send(Ok((buf, n))).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = filled_tx.send(Err(e));
                        break;
                    }
                }
            }
        });

        let mut md5 = md5::Md5::new();
        let mut sha1 = sha1::Sha1::new();
        let mut sha256 = sha2::Sha256::new();
        let mut bytes_done: u64 = 0;
        let mut last_report = std::time::Instant::now();

        while let Ok(item) = filled_rx.recv() {
            let (buf, n) = item?; // a read error propagates out unchanged
            if n == 0 {
                break;
            }
            // Run the three digests over this chunk in parallel: each is an
            // independent full pass, so they were three sequential CPU passes;
            // with rayon they overlap and wall-time drops to roughly the slowest
            // digest. Output is byte-identical -- each sees the same bytes in the
            // same order.
            let chunk = &buf[..n];
            rayon::join(
                || md5.update(chunk),
                || {
                    rayon::join(|| sha1.update(chunk), || sha256.update(chunk));
                },
            );
            bytes_done += n as u64;
            if last_report.elapsed() >= std::time::Duration::from_secs(1) {
                progress(bytes_done);
                last_report = std::time::Instant::now();
            }
            // Recycle the buffer. If the reader has already stopped this fails
            // harmlessly, and the loop ends when `filled` drains.
            let _ = free_tx.send(buf);
        }
        progress(bytes_done);

        Ok(HashResult {
            md5: format!("{:x}", md5.finalize()),
            sha1: format!("{:x}", sha1.finalize()),
            sha256: format!("{:x}", sha256.finalize()),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hashes_empty() {
        let result = compute_hashes(b"");
        // Known test vectors for empty string
        assert_eq!(result.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(result.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            result.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_compute_hashes_hello() {
        let result = compute_hashes(b"hello");
        assert_eq!(result.md5, "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(result.sha1, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
        assert_eq!(
            result.sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_compute_hashes_streaming() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut cursor = std::io::Cursor::new(data);
        let streaming_result = compute_hashes_streaming(&mut cursor, 8).unwrap();
        let direct_result = compute_hashes(data);
        assert_eq!(streaming_result, direct_result);
    }

    #[test]
    fn test_compute_hashes_streaming_with_progress_reports_total() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut cursor = std::io::Cursor::new(data);
        let mut calls: Vec<u64> = Vec::new();
        let result =
            compute_hashes_streaming_with_progress(&mut cursor, 8, |done| calls.push(done))
                .unwrap();
        // Final call always reports the total byte count
        assert_eq!(calls.last().copied(), Some(data.len() as u64));
        assert_eq!(result, compute_hashes(data));
    }

    #[test]
    fn test_compute_hashes_streaming_known_vector() {
        let data = b"hello";
        let mut cursor = std::io::Cursor::new(data);
        let result = compute_hashes_streaming(&mut cursor, 1024).unwrap();
        assert_eq!(result.md5, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn streaming_propagates_a_read_error_unchanged() {
        // The pipelined reader delivers a mid-stream error in-band; it must come
        // back out of this function as the same io::Error kind, not a hash of a
        // truncated stream.
        struct FailAfter {
            served: bool,
        }
        impl Read for FailAfter {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.served {
                    self.served = true;
                    buf[..4].copy_from_slice(b"data");
                    Ok(4)
                } else {
                    Err(std::io::Error::other("disk fell over"))
                }
            }
        }
        let mut reader = FailAfter { served: false };
        let err = compute_hashes_streaming(&mut reader, 8).expect_err("the read error surfaces");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn streaming_matches_direct_across_many_chunks() {
        // Multi-MiB input with a small buffer forces many chunks through the
        // parallel per-chunk digest path; the result must still equal a single
        // in-memory pass, byte-for-byte on all three digests.
        let data: Vec<u8> = (0..(3 * 1024 * 1024 + 777))
            .map(|i| (i * 31 + 7) as u8)
            .collect();
        let mut cursor = std::io::Cursor::new(&data);
        let streaming = compute_hashes_streaming(&mut cursor, 64 * 1024).unwrap();
        assert_eq!(streaming, compute_hashes(&data));
    }
}
