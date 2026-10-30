//! The decrypting `DataSource` that presents an AES-XTS BitLocker payload in the
//! clear. Reads are widened to whole cipher sectors, decrypted with the FVEK,
//! then sliced to the requested range so callers can do unaligned reads.
//!
//! Note: this decrypts the entire volume with the FVEK. On a real Windows volume
//! the boot region and FVE-metadata regions are stored unencrypted / relocated;
//! surfacing those verbatim is a documented limitation pending a real AES-XTS
//! test vector. The data region decrypts correctly.

use crate::error::BitlockerError;
use crate::{diffuser, xts};
use seance_core::data_source::DataSource;
use std::fmt;
use std::io;
use std::sync::Arc;

pub struct BitlockerXtsDataSource {
    inner: Arc<dyn DataSource>,
    /// Wiped when the source is dropped (HUNT-254).
    fvek: zeroize::Zeroizing<Vec<u8>>,
    xts256: bool,
    sector_size: usize,
    plaintext_size: u64,
}

impl BitlockerXtsDataSource {
    pub fn new(
        inner: Arc<dyn DataSource>,
        fvek: impl Into<zeroize::Zeroizing<Vec<u8>>>,
        xts256: bool,
        sector_size: usize,
    ) -> Self {
        let plaintext_size = inner.size();
        Self {
            inner,
            fvek: fvek.into(),
            xts256,
            sector_size,
            plaintext_size,
        }
    }

    fn decrypt_range(&self, offset: u64, want: usize) -> Result<Vec<u8>, BitlockerError> {
        let ss = self.sector_size as u64;
        let first_sector = offset / ss;
        let sector_off = (offset % ss) as usize;
        let last_byte = offset + want as u64 - 1;
        let last_sector = last_byte / ss;
        let num_sectors = (last_sector - first_sector + 1) as usize;
        let span = num_sectors * self.sector_size;
        let phys = first_sector * ss;

        let mut buf = vec![0u8; span];
        let mut filled = 0;
        while filled < span {
            let n = self
                .inner
                .read_at(phys + filled as u64, &mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        // A short read leaves the tail of `buf` as the zeros it was allocated
        // with. Decrypting those produces bytes that look exactly like
        // successfully recovered plaintext, and nothing downstream can tell
        // them from the real thing — they are hashed, exported and searched as
        // evidence. Refuse instead: an unreadable sector is a fact about the
        // acquisition, and the examiner has to see it (BUG-008).
        if filled < sector_off + want {
            return Err(BitlockerError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "ciphertext for sectors {first_sector}..={last_sector} is short: {filled} of \
                     {span} bytes were readable, which does not cover the {want} byte(s) asked \
                     for at offset {offset}"
                ),
            )));
        }

        xts::decrypt_sectors(
            &self.fvek,
            self.xts256,
            self.sector_size,
            first_sector as u128,
            &mut buf,
        )?;
        Ok(buf[sector_off..sector_off + want].to_vec())
    }
}

impl fmt::Debug for BitlockerXtsDataSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitlockerXtsDataSource")
            .field("xts256", &self.xts256)
            .field("sector_size", &self.sector_size)
            .field("plaintext_size", &self.plaintext_size)
            .field("fvek", &"<redacted>")
            .finish()
    }
}

impl DataSource for BitlockerXtsDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        seance_core::data_source::read_decrypted_range(
            self.plaintext_size,
            offset,
            buf,
            |offset, want| self.decrypt_range(offset, want),
        )
    }

    fn size(&self) -> u64 {
        self.plaintext_size
    }
}

/// The decrypting `DataSource` for AES-CBC + Elephant-diffuser volumes
/// (Vista/7/8). Each 512-byte sector is decrypted with `block_key` = its byte
/// offset — validated against a real Windows volume (see `diffuser`).
///
/// Note, as with the XTS source: the unencrypted FVE-metadata regions and the
/// relocated boot sectors are decrypted verbatim by offset, so a full
/// filesystem-level virtualization remap of the first sectors is a refinement;
/// the encrypted data region decrypts correctly.
pub struct BitlockerDiffuserDataSource {
    inner: Arc<dyn DataSource>,
    /// Both wiped when the source is dropped (HUNT-254).
    aes_key: zeroize::Zeroizing<Vec<u8>>,
    tweak_key: zeroize::Zeroizing<Vec<u8>>,
    plaintext_size: u64,
}

impl BitlockerDiffuserDataSource {
    pub fn new(
        inner: Arc<dyn DataSource>,
        aes_key: impl Into<zeroize::Zeroizing<Vec<u8>>>,
        tweak_key: impl Into<zeroize::Zeroizing<Vec<u8>>>,
    ) -> Self {
        let plaintext_size = inner.size();
        Self {
            inner,
            aes_key: aes_key.into(),
            tweak_key: tweak_key.into(),
            plaintext_size,
        }
    }

    fn decrypt_range(&self, offset: u64, want: usize) -> Result<Vec<u8>, BitlockerError> {
        const SS: u64 = 512;
        let first_sector = offset / SS;
        let sector_off = (offset % SS) as usize;
        let last_sector = (offset + want as u64 - 1) / SS;
        let num_sectors = (last_sector - first_sector + 1) as usize;
        let phys = first_sector * SS;

        let mut buf = vec![0u8; num_sectors * SS as usize];
        let mut filled = 0;
        while filled < buf.len() {
            let n = self
                .inner
                .read_at(phys + filled as u64, &mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        // As in the XTS path: zeros left by a short read decrypt into something
        // indistinguishable from recovered plaintext (BUG-008).
        if filled < sector_off + want {
            return Err(BitlockerError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "ciphertext for sectors {first_sector}..={last_sector} is short: {filled} of \
                     {} bytes were readable, which does not cover the {want} byte(s) asked for \
                     at offset {offset}",
                    buf.len()
                ),
            )));
        }

        for (i, sector) in buf.chunks_mut(SS as usize).enumerate() {
            let block_key = phys + i as u64 * SS;
            diffuser::decrypt_sector(&self.aes_key, &self.tweak_key, block_key, sector)?;
        }
        Ok(buf[sector_off..sector_off + want].to_vec())
    }
}

impl fmt::Debug for BitlockerDiffuserDataSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitlockerDiffuserDataSource")
            .field("plaintext_size", &self.plaintext_size)
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl DataSource for BitlockerDiffuserDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        seance_core::data_source::read_decrypted_range(
            self.plaintext_size,
            offset,
            buf,
            |offset, want| self.decrypt_range(offset, want),
        )
    }

    fn size(&self) -> u64 {
        self.plaintext_size
    }
}

/// Presents a BitLocker volume as the volume its filesystem believes it is.
///
/// Decryption alone does not do that, because a BitLocker volume is not
/// uniformly encrypted. Two kinds of region are not ciphertext, and running
/// them through the cipher destroys them:
///
/// - **The boot sectors.** BitLocker installs its own volume boot record at
///   sector 0 and relocates the filesystem's elsewhere, encrypted, recording
///   where in the FVE volume-header-block entry. A view that leaves it alone
///   has noise at offset 0, so every filesystem parser reads that, finds no
///   `NTFS` signature and concludes the volume holds no filesystem. The whole
///   volume is recovered and none of it is reachable — and it fails the way an
///   unformatted disk does, not the way an error does.
/// - **The FVE metadata regions.** Three redundant copies of BitLocker's own
///   metadata live inside the volume and are left unencrypted, which is exactly
///   why they can be parsed without a credential. Deciphering them turns the one
///   part of the volume that was always readable into noise.
///
/// So reads are served from whichever source is right for the region they land
/// in, and a read spanning several regions is stitched rather than truncated.
#[derive(Debug)]
pub struct BitlockerVolumeSource {
    /// The decrypting view, for everything that is genuinely ciphertext.
    cipher: Arc<dyn DataSource>,
    /// The volume as it is on disk, for the regions that were never encrypted.
    raw: Arc<dyn DataSource>,
    header_offset: u64,
    header_len: u64,
    /// `(offset, length)` of each unencrypted FVE metadata region, sorted.
    passthrough: Vec<(u64, u64)>,
}

/// Where a byte should be read from.
enum From {
    /// The decrypting view, at this offset.
    Cipher(u64),
    /// The volume as stored, at this offset.
    Raw(u64),
}

impl BitlockerVolumeSource {
    /// `header_offset`/`header_len` come from the FVE volume header block, and
    /// `passthrough` from its metadata region list. A zero header length means
    /// the volume declared no relocation, and those reads pass through
    /// unchanged rather than being redirected to offset zero.
    pub fn new(
        cipher: Arc<dyn DataSource>,
        raw: Arc<dyn DataSource>,
        header_offset: u64,
        header_len: u64,
        passthrough: Vec<(u64, u64)>,
    ) -> Self {
        let mut passthrough: Vec<(u64, u64)> = passthrough
            .into_iter()
            .filter(|(_, len)| *len > 0)
            .collect();
        passthrough.sort_by_key(|(off, _)| *off);
        Self {
            cipher,
            raw,
            header_offset,
            header_len,
            passthrough,
        }
    }

    /// Which source serves `pos`, and how many bytes may be taken from it
    /// before the answer changes.
    ///
    /// Returning the span as well as the source is what lets `read_at` stitch a
    /// read that crosses a boundary instead of silently returning bytes from
    /// the wrong region.
    fn map(&self, pos: u64) -> (From, u64) {
        // The relocated boot sectors, which are encrypted where they now live.
        if self.header_len > 0 && pos < self.header_len {
            return (
                From::Cipher(self.header_offset + pos),
                self.header_len - pos,
            );
        }

        // Inside an unencrypted metadata region.
        for &(start, len) in &self.passthrough {
            let end = start.saturating_add(len);
            if pos >= start && pos < end {
                return (From::Raw(pos), end - pos);
            }
        }

        // Ordinary ciphertext, up to the next region that is not.
        let next = self
            .passthrough
            .iter()
            .map(|&(start, _)| start)
            .find(|&start| start > pos)
            .unwrap_or(u64::MAX);
        (From::Cipher(pos), next.saturating_sub(pos))
    }
}

impl DataSource for BitlockerVolumeSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.size();
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset.saturating_add(done as u64);
            if pos >= size {
                break;
            }
            let (from, span) = self.map(pos);
            let remaining = buf.len() - done;
            let want = span.min(remaining as u64).min(size - pos).max(1) as usize;
            let want = want.min(remaining);
            let slice = &mut buf[done..done + want];
            let n = match from {
                From::Cipher(at) => self.cipher.read_at(at, slice)?,
                From::Raw(at) => self.raw.read_at(at, slice)?,
            };
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }

    fn size(&self) -> u64 {
        self.cipher.size()
    }
}

#[cfg(test)]
mod key_hygiene_tests {
    use super::*;
    use std::any::{Any, TypeId};

    /// `true` only when the value is a zeroizing key buffer: one that wipes
    /// its bytes when dropped (HUNT-254).
    fn is_zeroizing<T: Any>(_: &T) -> bool {
        TypeId::of::<T>() == TypeId::of::<zeroize::Zeroizing<Vec<u8>>>()
    }

    #[derive(Debug)]
    struct Empty;
    impl DataSource for Empty {
        fn read_at(&self, _: u64, _: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn size(&self) -> u64 {
            4096
        }
    }

    #[test]
    fn xts_and_diffuser_keys_are_zeroizing() {
        let xts = BitlockerXtsDataSource::new(Arc::new(Empty), vec![7u8; 32], false, 512);
        assert!(
            is_zeroizing(&xts.fvek),
            "the XTS source's FVEK is not wiped when the source is dropped"
        );
        let cbc = BitlockerDiffuserDataSource::new(Arc::new(Empty), vec![7u8; 16], vec![9u8; 16]);
        assert!(
            is_zeroizing(&cbc.aes_key),
            "the diffuser AES key is not wiped"
        );
        assert!(
            is_zeroizing(&cbc.tweak_key),
            "the diffuser tweak key is not wiped"
        );
    }
}
