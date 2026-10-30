//! The decrypting `DataSource` that presents a LUKS payload in the clear.

use crate::error::LuksError;
use crate::xts;
use seance_core::data_source::DataSource;
use std::fmt;
use std::io;
use std::sync::Arc;

/// Wraps the encrypted volume and decrypts sectors on demand.
///
/// `read_at` addresses the *plaintext* payload: byte 0 here is the first byte
/// after `payload_offset` on the encrypted device. Reads are widened to whole
/// cipher sectors, decrypted with the recovered master key, then sliced back to
/// the requested range so callers can do arbitrary unaligned reads.
pub struct LuksDecryptingDataSource {
    inner: Arc<dyn DataSource>,
    /// Wiped when the source is dropped (HUNT-254).
    master_key: zeroize::Zeroizing<Vec<u8>>,
    /// Byte offset of the payload within the encrypted volume.
    payload_offset: u64,
    sector_size: usize,
    /// Base XTS tweak for the first plaintext sector (0 for LUKS1).
    iv_offset: u128,
    plaintext_size: u64,
}

impl LuksDecryptingDataSource {
    pub fn new(
        inner: Arc<dyn DataSource>,
        master_key: impl Into<zeroize::Zeroizing<Vec<u8>>>,
        payload_offset: u64,
        sector_size: usize,
        iv_offset: u128,
    ) -> Self {
        let vol_size = inner.size();
        let plaintext_size = vol_size.saturating_sub(payload_offset);
        Self {
            inner,
            master_key: master_key.into(),
            payload_offset,
            sector_size,
            iv_offset,
            plaintext_size,
        }
    }

    fn decrypt_range(&self, offset: u64, want: usize) -> Result<Vec<u8>, LuksError> {
        let ss = self.sector_size as u64;
        let first_sector = offset / ss;
        let sector_off = (offset % ss) as usize;
        let last_byte = offset + want as u64 - 1;
        let last_sector = last_byte / ss;
        let num_sectors = (last_sector - first_sector + 1) as usize;

        let span = num_sectors * self.sector_size;
        let phys = self.payload_offset + first_sector * ss;

        let mut buf = vec![0u8; span];
        // Fill from the encrypted volume. A short read past the end of the
        // device is ordinary: the read is widened to whole cipher sectors, so
        // the tail beyond `plaintext_size` is never returned.
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
        // A shortfall that reaches the bytes actually being returned is not
        // ordinary. Those bytes are still zeros from the allocation, and
        // decrypting them yields something indistinguishable from recovered
        // plaintext — it is hashed, exported and searched as evidence with
        // nothing to mark it. Refuse: an unreadable sector is a fact about the
        // acquisition and the examiner has to see it (BUG-008).
        if filled < sector_off + want {
            return Err(LuksError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "ciphertext for sectors {first_sector}..={last_sector} is short: {filled} of \
                     {span} bytes were readable, which does not cover the {want} byte(s) asked \
                     for at offset {offset}"
                ),
            )));
        }

        let tweak_base = self.iv_offset + first_sector as u128;
        xts::decrypt_sectors(&self.master_key, self.sector_size, tweak_base, &mut buf)?;

        Ok(buf[sector_off..sector_off + want].to_vec())
    }
}

impl fmt::Debug for LuksDecryptingDataSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LuksDecryptingDataSource")
            .field("payload_offset", &self.payload_offset)
            .field("sector_size", &self.sector_size)
            .field("iv_offset", &self.iv_offset)
            .field("plaintext_size", &self.plaintext_size)
            .field("master_key", &"<redacted>")
            .finish()
    }
}

impl DataSource for LuksDecryptingDataSource {
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
    fn master_key_is_held_in_a_zeroizing_buffer() {
        let src = LuksDecryptingDataSource::new(Arc::new(Empty), vec![7u8; 64], 0, 512, 0);
        assert!(
            is_zeroizing(&src.master_key),
            "the LUKS master key is not wiped when the source is dropped"
        );
    }
}
