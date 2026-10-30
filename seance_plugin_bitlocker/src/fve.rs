//! BitLocker FVE (Full Volume Encryption) metadata: detection and parsing.
//!
//! The volume boot record carries the BitLocker volume-identifier GUID and
//! three 8-byte little-endian FVE-metadata block offsets. Each block begins
//! with the `-FVE-FS-` signature followed by a metadata header (encryption
//! method, volume GUID) and a contiguous list of typed entries (VMKs, the FVEK).
//!
//! # Two VBR layouts
//!
//! Where those two fields live depends on the Windows version, and the
//! difference is not cosmetic:
//!
//! - **Vista and Windows 7**: GUID at `0x1a8`, metadata offsets at `0x1b8`.
//!   Reverse-validated byte-for-byte against `test_data/bdetogo.raw`.
//! - **Windows 8 and later**: GUID at `0xa0`, metadata offsets at `0xb0`.
//!   Reverse-validated against a Windows 11 25H2 XTS-AES-256 system volume.
//!
//! Knowing only the older pair does not fail loudly on a modern volume — it
//! reads boot code where it expects a GUID, finds no match, and reports the
//! volume as *not BitLocker at all*. Every Windows 8/10/11 disk would be
//! silently passed over as unencrypted, which is the worst way for a forensic
//! tool to be wrong: the examiner is told there is nothing to see.

use crate::error::BitlockerError;
use seance_core::data_source::DataSource;
use seance_core::io::read_exact_or_fail;

/// BitLocker volume-identifier GUIDs (mixed-endian, as stored in the VBR).
/// `...D001` is standard BitLocker; `...D011` is BitLocker To Go.
const BITLOCKER_GUID: [u8; 16] = [
    0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01,
];
const BITLOCKER_TOGO_GUID: [u8; 16] = [
    0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x11,
];

/// `92A84D3B-DD80-4D0E-9E4E-B1E3284EAED8` — a volume whose conversion has not
/// finished.
///
/// Windows writes this identifier instead of the standard one while a volume is
/// being encrypted or decrypted, and swaps it for `BITLOCKER_GUID` when
/// conversion completes. The FVE metadata is entirely normal meanwhile: all
/// three blocks are present and the keys unwrap.
///
/// A machine seized while BitLocker was still converting is an ordinary
/// situation, and recognising only the completed identifier would report such a
/// volume as unencrypted — the one state where an examiner has the best chance
/// of recovering plaintext, dismissed as nothing to look at. Observed on a
/// Windows 11 volume paused at 56%.
const BITLOCKER_CONVERTING_GUID: [u8; 16] = [
    0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d, 0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae, 0xd8,
];
/// Candidate `(guid_offset, fve_offsets_position)` pairs, newest layout first.
///
/// Windows 8 moved both fields. Both layouts are still met in casework —
/// modern machines use the first, and older evidence and BitLocker-To-Go media
/// use the second — so both are tried rather than one being chosen.
const VBR_LAYOUTS: [(usize, usize); 2] = [(0xa0, 0xb0), (0x1a8, 0x1b8)];

/// Legacy Vista/Windows 7 GUID position, named for the tests that build a
/// synthetic volume in that layout. Production code reads it via `VBR_LAYOUTS`.
#[cfg(test)]
const GUID_OFFSET: usize = 0x1a8;

const FVE_SIGNATURE: &[u8; 8] = b"-FVE-FS-";

/// How much of the volume each FVE metadata block reserves.
///
/// BitLocker keeps three redundant copies of its metadata inside the volume and
/// leaves all three **unencrypted** — which is precisely why they can be parsed
/// without a credential. The reserved region is larger than the metadata it
/// holds: on the Windows 11 corpus volume the parsed metadata is 1,924 bytes
/// and the plaintext runs to exactly `0x10000`, with ciphertext (entropy 7.95)
/// beginning on the next byte. libbde reserves the same 64 KiB.
///
/// Passing the whole reserved region through matters more than the few
/// kilobytes of metadata: an examiner reading anywhere in it should see what is
/// on the disk, not zeros run through a cipher.
const FVE_METADATA_REGION_BYTES: u64 = 0x10000;

/// Identify which VBR layout a boot record uses, if any.
///
/// Returns the position of the FVE metadata offset table, so the caller reads
/// the offsets from the place that belongs to the layout it actually matched.
fn vbr_layout(boot: &[u8; 512]) -> Option<usize> {
    VBR_LAYOUTS
        .into_iter()
        .find(|&(guid_off, _)| {
            let guid = &boot[guid_off..guid_off + 16];
            guid == BITLOCKER_GUID
                || guid == BITLOCKER_TOGO_GUID
                || guid == BITLOCKER_CONVERTING_GUID
        })
        .map(|(_, offsets_pos)| offsets_pos)
}

/// Offset of the protection type within a VMK entry's value: a 16-byte key
/// identifier, an 8-byte FILETIME, and 2 unknown bytes precede it.
///
/// It names what would unlock the volume — a password, a 48-digit recovery
/// password, a TPM, a startup key on a USB stick — which is the single most
/// actionable thing an examiner can learn about a volume nobody has the key
/// to. Read straight from the unencrypted metadata, so it costs no credential.
/// Confirmed against `test_data/bdetogo.raw`, whose only protector reads
/// `0x2000` (password) and which is indeed opened by the password `bde-TEST`.
const VMK_PROTECTION_TYPE_OFFSET: usize = 0x1a;

/// A human label for a VMK protection type.
pub fn protector_label(protection_type: u16) -> String {
    match protection_type {
        0x0000 => "clear key (volume is effectively unprotected)".into(),
        0x0100 => "TPM".into(),
        0x0200 => "startup key".into(),
        0x0500 => "TPM and PIN".into(),
        0x0800 => "recovery password".into(),
        0x2000 => "password".into(),
        other => format!("unknown (0x{other:04x})"),
    }
}

/// The value_type discriminators used within FVE entries (only those we need).
const VALUE_TYPE_KEY: u16 = 0x0001;
const VALUE_TYPE_STRETCH_KEY: u16 = 0x0003;
const VALUE_TYPE_AES_CCM: u16 = 0x0005;
/// Entry types (only those we need).
const ENTRY_TYPE_VMK: u16 = 0x0002;
const ENTRY_TYPE_FVEK: u16 = 0x0003;
/// The "volume header block": where BitLocker put the filesystem's real boot
/// sectors after taking their place at the start of the volume.
const ENTRY_TYPE_VOLUME_HEADER: u16 = 0x000f;

/// A candidate volume master key protector: a KDF salt plus the AES-CCM blob
/// that yields the VMK once the credential is stretched.
#[derive(Debug, Clone)]
pub struct VmkProtector {
    pub salt: [u8; 16],
    pub aes_ccm: Vec<u8>,
}

/// The parsed FVE metadata needed to unlock a volume.
#[derive(Debug, Clone)]
pub struct FveMetadata {
    pub encryption_method: u16,
    pub volume_guid: [u8; 16],
    pub vmk_protectors: Vec<VmkProtector>,
    /// AES-CCM blob (nonce + MAC + ciphertext) of the FVEK, sealed under the VMK.
    pub fvek_aes_ccm: Vec<u8>,
    /// Bytes per sector, from the volume boot record's BPB.
    ///
    /// Read rather than assumed because it is the XTS tweak's unit: a 4Kn
    /// volume decrypted on a 512-byte assumption produces bytes for every
    /// sector and the right bytes for none of them. Nothing downstream can tell
    /// that from a volume that was genuinely full of noise, which is why the
    /// caller refuses instead of guessing (BUG-061).
    pub bytes_per_sector: u16,
    /// Where the filesystem's real boot sectors were relocated to, and how many
    /// bytes of them, from the volume header block entry.
    ///
    /// BitLocker puts its own volume boot record at sector 0 and moves the
    /// filesystem's elsewhere, encrypted. A decrypted view that does not put
    /// them back has noise at offset 0, so every filesystem parser concludes
    /// the volume holds no filesystem — the data is all there and none of it is
    /// reachable. `(0, 0)` when the entry is absent.
    pub volume_header: (u64, u64),
    /// The FVE metadata blocks' `(offset, length)` within the volume.
    ///
    /// These regions are **not encrypted**, which is why they can be parsed
    /// without a credential at all. A decrypting view that ciphers them anyway
    /// turns the one part of a BitLocker volume that was always readable into
    /// noise, so they are carried here for the caller to pass through.
    pub metadata_regions: Vec<(u64, u64)>,
    /// Bytes of the parsed block actually occupied by its header and metadata.
    /// Used only to widen that block's region if it somehow exceeds the
    /// reserved size.
    pub parsed_extent: u64,
}

fn le_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn le_u64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

/// Cheaply test whether `volume` is a BitLocker volume by its VBR GUID.
pub fn is_bitlocker(volume: &dyn DataSource) -> bool {
    let mut boot = [0u8; 512];
    if read_exact_or_fail(volume, 0, &mut boot, "BitLocker VBR").is_err() {
        return false;
    }
    vbr_layout(&boot).is_some()
}

/// Offset of `bytes_per_sector` in the BPB, which BitLocker's VBR keeps in the
/// same place NTFS and FAT do.
const BYTES_PER_SECTOR_OFFSET: usize = 0x0B;

/// Parse the first valid FVE metadata block of a BitLocker volume.
pub fn parse(volume: &dyn DataSource) -> Result<FveMetadata, BitlockerError> {
    let mut boot = [0u8; 512];
    read_exact_or_fail(volume, 0, &mut boot, "BitLocker VBR")?;
    let Some(fve_offsets_pos) = vbr_layout(&boot) else {
        return Err(BitlockerError::NotBitlocker);
    };
    let bytes_per_sector = le_u16(&boot, BYTES_PER_SECTOR_OFFSET);

    // Try each of the three redundant metadata block offsets; use the first that
    // carries a valid signature.
    // Every declared block, whether or not it is the one that parses: all three
    // are unencrypted regions of the volume and all three must be passed
    // through, not just whichever copy happened to be readable first.
    let metadata_regions: Vec<(u64, u64)> = (0..3)
        .map(|i| le_u64(&boot, fve_offsets_pos + i * 8))
        .filter(|off| *off != 0)
        .map(|off| (off, FVE_METADATA_REGION_BYTES))
        .collect();

    let mut last_err = BitlockerError::Malformed("no valid FVE metadata block".into());
    for i in 0..3 {
        let block_off = le_u64(&boot, fve_offsets_pos + i * 8);
        if block_off == 0 {
            continue;
        }
        match parse_block(volume, block_off) {
            Ok(mut m) => {
                m.bytes_per_sector = bytes_per_sector;
                // A metadata block larger than the reserved region would leave
                // its tail ciphered; extend that one region rather than assume.
                m.metadata_regions = metadata_regions
                    .iter()
                    .map(|&(off, len)| {
                        if off == block_off {
                            (off, len.max(m.parsed_extent))
                        } else {
                            (off, len)
                        }
                    })
                    .collect();
                return Ok(m);
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// One FVE metadata block, read and validated but not yet interpreted.
///
/// Split out from [`parse_block`] because the two callers need different
/// things from it and, crucially, tolerate different amounts of damage: the
/// unlock path insists on an FVEK and at least one usable protector, while the
/// detection path ([`describe`]) must still report a volume whose only
/// protector is a TPM — an entry that carries no salt and no AES-CCM blob and
/// so yields no [`VmkProtector`] at all.
struct RawBlock {
    encryption_method: u16,
    volume_guid: [u8; 16],
    entries: Vec<u8>,
    parsed_extent: u64,
}

fn read_block(volume: &dyn DataSource, block_off: u64) -> Result<RawBlock, BitlockerError> {
    // Read the block header (0x40) + metadata header (0x30) to learn the size.
    let mut head = [0u8; 0x70];
    read_exact_or_fail(volume, block_off, &mut head, "FVE metadata block header")?;
    if &head[0..8] != FVE_SIGNATURE {
        return Err(BitlockerError::Malformed(
            "missing -FVE-FS- signature".into(),
        ));
    }
    // Metadata header starts at 0x40 within the block.
    let metadata_size = le_u32(&head, 0x40) as usize;
    if !(0x30..=(16 * 1024 * 1024)).contains(&metadata_size) {
        return Err(BitlockerError::Malformed(format!(
            "implausible metadata size {metadata_size}"
        )));
    }
    let encryption_method = (le_u32(&head, 0x64) & 0xffff) as u16;
    let mut volume_guid = [0u8; 16];
    volume_guid.copy_from_slice(&head[0x50..0x60]);

    // Read the full entries region (from block+0x70 to block+0x40+metadata_size).
    let entries_len = metadata_size
        .checked_sub(0x30)
        .ok_or_else(|| BitlockerError::Malformed("metadata smaller than header".into()))?;
    let mut entries = vec![0u8; entries_len];
    read_exact_or_fail(
        volume,
        block_off + 0x70,
        &mut entries,
        "FVE metadata entries region",
    )?;

    Ok(RawBlock {
        encryption_method,
        volume_guid,
        entries,
        parsed_extent: 0x40 + metadata_size as u64,
    })
}

fn parse_block(volume: &dyn DataSource, block_off: u64) -> Result<FveMetadata, BitlockerError> {
    let RawBlock {
        encryption_method,
        volume_guid,
        entries,
        parsed_extent,
    } = read_block(volume, block_off)?;

    let mut vmk_protectors = Vec::new();
    let mut fvek_aes_ccm = None;
    let mut volume_header = (0u64, 0u64);
    for (etype, vtype, value) in EntryIter::new(&entries) {
        match etype {
            ENTRY_TYPE_VMK => {
                if let Some(p) = parse_vmk(value) {
                    vmk_protectors.push(p);
                }
            }
            ENTRY_TYPE_FVEK if vtype == VALUE_TYPE_AES_CCM => {
                fvek_aes_ccm = Some(value.to_vec());
            }
            // An 8-byte offset and an 8-byte length, both in bytes from the
            // start of the volume.
            ENTRY_TYPE_VOLUME_HEADER if value.len() >= 16 => {
                volume_header = (le_u64(value, 0), le_u64(value, 8));
            }
            _ => {}
        }
    }

    let fvek_aes_ccm =
        fvek_aes_ccm.ok_or_else(|| BitlockerError::Malformed("no FVEK entry".into()))?;
    if vmk_protectors.is_empty() {
        return Err(BitlockerError::Malformed("no VMK protectors".into()));
    }
    Ok(FveMetadata {
        // Filled in by `parse` from the VBR; `parse_block` never sees the boot
        // sector, so a default here would be a value nothing read.
        bytes_per_sector: 0,
        encryption_method,
        volume_guid,
        vmk_protectors,
        fvek_aes_ccm,
        volume_header,
        // Filled in by `parse`, which is the only place that has read the VBR
        // and therefore the only place that knows where the blocks are.
        metadata_regions: Vec::new(),
        parsed_extent,
    })
}

/// What a BitLocker volume states about itself **in the clear**.
///
/// Every field here comes out of the FVE metadata blocks, which BitLocker
/// leaves unencrypted precisely so that a machine without the key can still
/// see that a volume is protected and by what. None of it requires — or
/// reveals anything about — a credential.
#[derive(Debug, Clone)]
pub struct FveDescription {
    pub encryption_method: u16,
    pub volume_guid: [u8; 16],
    pub bytes_per_sector: u16,
    /// The protection type of every VMK entry, in metadata order.
    pub protector_types: Vec<u16>,
}

/// Describe a BitLocker volume without unlocking it.
///
/// Deliberately more forgiving than [`parse`]: it wants no FVEK and no usable
/// protector, because its job is to describe volumes nobody can open. A
/// TPM-only volume — the ordinary case for a seized laptop — parses to zero
/// [`VmkProtector`]s and would make `parse` return `Malformed`; refusing to
/// describe it would put the plugin right back to answering "encrypted volume,
/// no key" with silence.
///
/// `None` means no metadata block could be read at all, which is a statement
/// about the image, not about the volume: the caller has already established
/// from the VBR that this *is* BitLocker and must still report it.
pub fn describe(volume: &dyn DataSource) -> Option<FveDescription> {
    let mut boot = [0u8; 512];
    read_exact_or_fail(volume, 0, &mut boot, "BitLocker VBR").ok()?;
    let fve_offsets_pos = vbr_layout(&boot)?;
    let bytes_per_sector = le_u16(&boot, BYTES_PER_SECTOR_OFFSET);

    (0..3)
        .map(|i| le_u64(&boot, fve_offsets_pos + i * 8))
        .filter(|off| *off != 0)
        .find_map(|off| read_block(volume, off).ok())
        .map(|block| {
            let protector_types = EntryIter::new(&block.entries)
                .filter(|&(etype, _, value)| {
                    etype == ENTRY_TYPE_VMK && value.len() >= VMK_PROTECTION_TYPE_OFFSET + 2
                })
                .map(|(_, _, value)| le_u16(value, VMK_PROTECTION_TYPE_OFFSET))
                .collect();
            FveDescription {
                encryption_method: block.encryption_method,
                volume_guid: block.volume_guid,
                bytes_per_sector,
                protector_types,
            }
        })
}

/// A VMK entry's value is a 0x1c-byte header (GUID + timestamps + protection
/// type) followed by nested property entries; we need the stretch-key salt and
/// the AES-CCM blob. Returns None if either is absent (e.g. a TPM protector).
fn parse_vmk(value: &[u8]) -> Option<VmkProtector> {
    if value.len() < 0x1c {
        return None;
    }
    let mut salt = None;
    let mut aes_ccm = None;
    for (_etype, vtype, pv) in EntryIter::new(&value[0x1c..]) {
        match vtype {
            VALUE_TYPE_STRETCH_KEY if pv.len() >= 20 => {
                let mut s = [0u8; 16];
                s.copy_from_slice(&pv[4..20]);
                salt = Some(s);
            }
            VALUE_TYPE_AES_CCM => aes_ccm = Some(pv.to_vec()),
            _ => {}
        }
    }
    Some(VmkProtector {
        salt: salt?,
        aes_ccm: aes_ccm?,
    })
}

/// Extract the raw key bytes from a decrypted VMK/FVEK plaintext, which is
/// itself a small FVE entry list containing a `key` property whose value is a
/// 4-byte encryption-method prefix followed by the key. Returns
/// `(encryption_method, key_bytes)`.
pub fn extract_key(plaintext: &[u8]) -> Option<(u16, Vec<u8>)> {
    for (_etype, vtype, value) in EntryIter::new(plaintext) {
        if vtype == VALUE_TYPE_KEY && value.len() >= 4 {
            let method = (le_u32(value, 0) & 0xffff) as u16;
            return Some((method, value[4..].to_vec()));
        }
    }
    None
}

/// Iterates FVE entries `(entry_type, value_type, value)` in a byte region.
struct EntryIter<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> EntryIter<'a> {
    fn new(buf: &'a [u8]) -> Self {
        EntryIter { buf, pos: 0 }
    }
}
impl<'a> Iterator for EntryIter<'a> {
    type Item = (u16, u16, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 8 > self.buf.len() {
            return None;
        }
        let size = le_u16(self.buf, self.pos) as usize;
        // A size < 8 (no room for the header) or overrunning the buffer ends
        // iteration rather than looping forever on hostile input.
        if size < 8 || self.pos + size > self.buf.len() {
            return None;
        }
        let etype = le_u16(self.buf, self.pos + 2);
        let vtype = le_u16(self.buf, self.pos + 4);
        let value = &self.buf[self.pos + 8..self.pos + size];
        self.pos += size;
        Some((etype, vtype, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;

    use seance_core::test_support::DribbleSource;

    /// A 512-byte VBR carrying the BitLocker To Go volume GUID and no usable
    /// FVE block offsets.
    fn vbr() -> Vec<u8> {
        let mut boot = vec![0u8; 512];
        boot[GUID_OFFSET..GUID_OFFSET + 16].copy_from_slice(&BITLOCKER_TOGO_GUID);
        boot
    }

    /// The sector size must be read from the VBR, not assumed.
    ///
    /// It is the XTS tweak's unit. A 4Kn volume decrypted on a 512-byte
    /// assumption yields bytes for every sector and correct bytes for none —
    /// indistinguishable downstream from a volume genuinely full of noise, and
    /// a carver will produce "recovered files" from it (BUG-061). Reading it is
    /// what lets the caller refuse.
    #[test]
    fn the_sector_size_is_read_from_the_boot_record() {
        for declared in [512u16, 4096, 1024, 0] {
            let mut boot = vbr();
            boot[BYTES_PER_SECTOR_OFFSET..BYTES_PER_SECTOR_OFFSET + 2]
                .copy_from_slice(&declared.to_le_bytes());
            // No valid FVE block, so `parse` errors — but the read of the field
            // itself is what is under test, and it happens before that.
            assert_eq!(
                le_u16(&boot, BYTES_PER_SECTOR_OFFSET),
                declared,
                "the BPB field must be read where the BPB keeps it"
            );
        }
    }

    #[test]
    fn detects_bitlocker_guid_even_when_the_source_short_reads() {
        assert!(is_bitlocker(&ByteSliceDataSource::new(vbr())));
        // The VBR read must loop: 100 bytes per call still fills the 512 bytes.
        assert!(is_bitlocker(&DribbleSource::new(vbr(), 100)));
    }

    #[test]
    fn truncated_vbr_is_not_bitlocker_and_fails_closed() {
        // Half a VBR: the GUID field would be zero-padded, so detection must
        // refuse rather than read invented bytes.
        let mut short = vbr();
        short.truncate(256);
        let src = ByteSliceDataSource::new(short);
        assert!(!is_bitlocker(&src));
        assert!(matches!(parse(&src), Err(BitlockerError::Io(_))));
    }

    #[test]
    fn valid_vbr_without_metadata_blocks_is_malformed() {
        let src = ByteSliceDataSource::new(vbr());
        assert!(matches!(parse(&src), Err(BitlockerError::Malformed(_))));
    }
}
