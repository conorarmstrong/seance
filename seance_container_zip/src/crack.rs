//! Password verification for encrypted ZIP archives.
//!
//! A verifier for the [`seance_crack`](https://docs) engine: given the archive
//! bytes and a candidate password, decide whether the password is correct. Both
//! ZIP encryption schemes are covered by the `zip` crate's `by_index_decrypt`:
//! traditional PKWARE (ZipCrypto) and WinZip AES (AE-1/AE-2). A candidate is
//! only reported correct when an *encrypted* entry both decrypts and reads to its
//! end without a CRC/authentication error, so a ZipCrypto 1-in-256 check-byte
//! collision cannot pass as a hit.
//!
//! The archive is opened over an in-memory cursor; the caller bounds how much of
//! the archive it reads in.

use std::io::{Cursor, Read};
use zip::result::ZipError;

/// Whether entry `i` of `archive` is encrypted. The `zip` crate has no public
/// accessor for the flag, but `by_index` (no password) returns the distinctive
/// `PASSWORD_REQUIRED` error for exactly the encrypted entries, so that is the
/// authoritative signal.
fn entry_is_encrypted<R: Read + std::io::Seek>(archive: &mut zip::ZipArchive<R>, i: usize) -> bool {
    matches!(
        archive.by_index(i),
        Err(ZipError::UnsupportedArchive(msg)) if msg == ZipError::PASSWORD_REQUIRED
    )
}

/// The outcome of testing one password against an archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipVerdict {
    /// The password correctly decrypts an encrypted entry (read to EOF, CRC OK).
    Correct,
    /// The archive has an encrypted entry and the password is wrong.
    Wrong,
    /// The archive parsed but holds no encrypted entry — nothing to crack.
    NotEncrypted,
    /// The archive could not be parsed at all.
    Unreadable,
}

/// Verify `password` against the single encrypted entry at `index`, reading it
/// **fully to EOF** so the `zip` crate runs its integrity check — the CRC for
/// ZipCrypto, the HMAC for AES. Returning before EOF would skip that check and
/// let a wrong password whose cheap 1-in-256 check byte collides pass as correct,
/// so there is deliberately no read cap here: correctness over a bounded run.
fn verify_entry<R: Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    index: usize,
    password: &str,
) -> ZipVerdict {
    match archive.by_index_decrypt(index, password.as_bytes()) {
        // Encrypted entry, wrong password (validation value / HMAC header failed).
        Err(zip::result::ZipError::InvalidPassword) => ZipVerdict::Wrong,
        Ok(mut file) => {
            // std::io::copy reads until the entry reader returns EOF, at which
            // point the crate validates CRC (ZipCrypto) / HMAC (AES). Only a
            // clean read to EOF proves the password.
            match std::io::copy(&mut file, &mut std::io::sink()) {
                Ok(_) => ZipVerdict::Correct,
                // Bytes decrypted past the check byte but failed the integrity
                // check: a collision, not the real password.
                Err(_) => ZipVerdict::Wrong,
            }
        }
        Err(_) => ZipVerdict::Wrong,
    }
}

/// The encrypted entry with the **smallest** uncompressed size, so verification
/// (which must read the whole entry to reach the integrity check) costs as little
/// as the archive allows. Returns `None` when no entry is encrypted.
fn smallest_encrypted_index<R: Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
) -> Option<usize> {
    let mut best: Option<(usize, u64)> = None;
    for i in 0..archive.len() {
        if !entry_is_encrypted(archive, i) {
            continue;
        }
        // Uncompressed size from the central directory (no password needed).
        let size = archive
            .by_index_raw(i)
            .map(|f| f.size())
            .unwrap_or(u64::MAX);
        if best.is_none_or(|(_, b)| size < b) {
            best = Some((i, size));
        }
    }
    best.map(|(i, _)| i)
}

/// Test `password` against the encrypted ZIP in `archive_bytes` (one-shot). For a
/// dictionary run, prefer [`ZipCracker`], which parses the archive once.
pub fn verify_zip_password(archive_bytes: &[u8], password: &str) -> ZipVerdict {
    let mut archive = match zip::ZipArchive::new(Cursor::new(archive_bytes)) {
        Ok(a) => a,
        Err(_) => return ZipVerdict::Unreadable,
    };
    match smallest_encrypted_index(&mut archive) {
        Some(idx) => verify_entry(&mut archive, idx, password),
        None => ZipVerdict::NotEncrypted,
    }
}

/// Whether `archive_bytes` is a parseable ZIP with at least one encrypted entry —
/// the precondition for cracking. Cheap: reads the central directory only.
pub fn has_encrypted_entry(archive_bytes: &[u8]) -> bool {
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(archive_bytes)) else {
        return false;
    };
    smallest_encrypted_index(&mut archive).is_some()
}

/// A ZIP opened once for a dictionary/mask crack run: the central directory is
/// parsed and the target encrypted entry chosen a single time, then every
/// candidate is tested against that cached state. Correctness is identical to
/// [`verify_zip_password`]; only the per-candidate central-directory re-parse is
/// removed.
pub struct ZipCracker {
    archive: std::cell::RefCell<zip::ZipArchive<Cursor<Vec<u8>>>>,
    /// The smallest encrypted entry to verify against, chosen once.
    verify_index: Option<usize>,
}

impl ZipCracker {
    /// Open `archive_bytes` and pick the entry to verify against. Fails only when
    /// the bytes are not a parseable ZIP.
    pub fn open(archive_bytes: Vec<u8>) -> Result<Self, ZipVerdict> {
        let mut archive =
            zip::ZipArchive::new(Cursor::new(archive_bytes)).map_err(|_| ZipVerdict::Unreadable)?;
        let verify_index = smallest_encrypted_index(&mut archive);
        Ok(Self {
            archive: std::cell::RefCell::new(archive),
            verify_index,
        })
    }

    /// Whether the archive has an encrypted entry to crack.
    pub fn has_encrypted_entry(&self) -> bool {
        self.verify_index.is_some()
    }

    /// Test one candidate password against the cached archive.
    pub fn verify(&self, password: &str) -> ZipVerdict {
        match self.verify_index {
            Some(idx) => verify_entry(&mut self.archive.borrow_mut(), idx, password),
            None => ZipVerdict::NotEncrypted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Command;

    /// Build a small file on disk, then a password-protected zip of it using the
    /// given `zip`/`7z` invocation. Returns the archive bytes, or `None` if the
    /// tool is unavailable (the test then skips rather than failing on a machine
    /// without it).
    fn make_encrypted_zip(
        build: impl FnOnce(&std::path::Path, &std::path::Path) -> bool,
    ) -> Option<Vec<u8>> {
        let dir = std::env::temp_dir().join(format!("seance_zipcrack_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).ok()?;
        let plain = dir.join("secret.txt");
        let mut f = std::fs::File::create(&plain).ok()?;
        f.write_all(b"the quick brown fox jumps over the lazy dog, repeatedly and at length")
            .ok()?;
        drop(f);
        let archive = dir.join("out.zip");
        let ok = build(&plain, &archive);
        let bytes = if ok {
            std::fs::read(&archive).ok()
        } else {
            None
        };
        let _ = std::fs::remove_dir_all(&dir);
        bytes
    }

    #[test]
    fn verifies_a_zipcrypto_password_and_rejects_a_wrong_one() {
        let Some(bytes) = make_encrypted_zip(|plain, archive| {
            // `zip -e` produces a traditional ZipCrypto archive.
            Command::new("zip")
                .args([
                    "-j",
                    "-e",
                    "-P",
                    "s3cr3t",
                    archive.to_str().unwrap(),
                    plain.to_str().unwrap(),
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }) else {
            eprintln!("skipping: `zip` not available");
            return;
        };
        assert!(has_encrypted_entry(&bytes), "the archive is encrypted");
        assert_eq!(verify_zip_password(&bytes, "s3cr3t"), ZipVerdict::Correct);
        assert_eq!(verify_zip_password(&bytes, "wrong"), ZipVerdict::Wrong);
    }

    #[test]
    fn verifies_a_winzip_aes_password_and_rejects_a_wrong_one() {
        let Some(bytes) = make_encrypted_zip(|plain, archive| {
            // 7z with AES-256 produces a WinZip AES archive.
            Command::new("7z")
                .args([
                    "a",
                    "-tzip",
                    "-mem=AES256",
                    "-ps3cr3t",
                    archive.to_str().unwrap(),
                    plain.to_str().unwrap(),
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }) else {
            eprintln!("skipping: `7z` not available");
            return;
        };
        assert!(has_encrypted_entry(&bytes), "the AES archive is encrypted");
        assert_eq!(verify_zip_password(&bytes, "s3cr3t"), ZipVerdict::Correct);
        assert_eq!(verify_zip_password(&bytes, "nope"), ZipVerdict::Wrong);
    }

    #[test]
    fn an_unencrypted_zip_is_not_crackable() {
        let Some(bytes) = make_encrypted_zip(|plain, archive| {
            Command::new("zip")
                .args(["-j", archive.to_str().unwrap(), plain.to_str().unwrap()])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }) else {
            eprintln!("skipping: `zip` not available");
            return;
        };
        assert!(!has_encrypted_entry(&bytes));
        assert_eq!(
            verify_zip_password(&bytes, "anything"),
            ZipVerdict::NotEncrypted
        );
    }

    #[test]
    fn verifies_an_entry_larger_than_the_old_read_cap() {
        // Regression: a previous 16 MiB read cap stopped before EOF on a large
        // entry, so the CRC/HMAC was never checked and a wrong password could be
        // reported correct. Use a ~20 MiB entry (zeros compress tiny) and confirm
        // the correct password verifies (full read to EOF) and a wrong one fails.
        let dir = std::env::temp_dir().join(format!("seance_ziplarge_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let plain = dir.join("big.bin");
        std::fs::write(&plain, vec![0u8; 20 * 1024 * 1024]).unwrap();
        let archive = dir.join("big.zip");
        let built = Command::new("zip")
            .args([
                "-j",
                "-e",
                "-P",
                "s3cr3t",
                archive.to_str().unwrap(),
                plain.to_str().unwrap(),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let bytes = if built {
            std::fs::read(&archive).ok()
        } else {
            None
        };
        let _ = std::fs::remove_dir_all(&dir);
        let Some(bytes) = bytes else {
            eprintln!("skipping: `zip` not available");
            return;
        };
        assert_eq!(verify_zip_password(&bytes, "s3cr3t"), ZipVerdict::Correct);
        assert_eq!(verify_zip_password(&bytes, "wrong"), ZipVerdict::Wrong);
    }

    #[test]
    fn zip_cracker_reuses_the_parsed_archive_across_candidates() {
        let Some(bytes) = make_encrypted_zip(|plain, archive| {
            Command::new("zip")
                .args([
                    "-j",
                    "-e",
                    "-P",
                    "s3cr3t",
                    archive.to_str().unwrap(),
                    plain.to_str().unwrap(),
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }) else {
            eprintln!("skipping: `zip` not available");
            return;
        };
        let cracker = ZipCracker::open(bytes).expect("parseable zip");
        assert!(cracker.has_encrypted_entry());
        // Multiple candidates against one parsed archive.
        assert_eq!(cracker.verify("nope"), ZipVerdict::Wrong);
        assert_eq!(cracker.verify("s3cr3t"), ZipVerdict::Correct);
        assert_eq!(cracker.verify("also-wrong"), ZipVerdict::Wrong);
    }

    #[test]
    fn garbage_is_unreadable_not_a_panic() {
        assert_eq!(
            verify_zip_password(b"not a zip file at all", "x"),
            ZipVerdict::Unreadable
        );
    }
}
