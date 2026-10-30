//! One hand-built memory image for the fixtures that write structures by
//! address.
//!
//! Five copies of this existed — `poolscan`, `netscan`, `automagic_dtb`,
//! `environment_test_support` and `registry_test_support` — and two of them
//! were byte-identical bar their indentation. The other three had drifted into
//! different method *names* for the same operation (`put64` against `put_u64`)
//! and different extras, which is how a reader ends up unsure whether two
//! fixtures that look alike behave alike.
//!
//! The size stays a caller's constant rather than a constant here: the modules
//! genuinely need different images (`0x3_0000` for a pool fixture, `0x40_0000`
//! where a kernel scan has to cross several megabytes), and baking one size in
//! would either waste memory in every small test or silently truncate a large
//! one.
//!
//! # Why write by address rather than by offset
//!
//! A structure under test is declared at the address it really occupies, so a
//! failing assertion points at the fixture line that wrote it instead of at
//! arithmetic performed at the call site. Both halves of the address space map
//! onto the same bytes, so an address is either its own offset or [`KERNEL`]
//! plus it.

// No `#![cfg(test)]` here: lib.rs already declares this module under
// `#[cfg(test)]`, and gating it twice is the duplicate clippy reports. The
// declaration site is the one that decides whether the module exists at all,
// so that is the gate that stays.

/// Where the kernel half of the fixture's address space begins.
///
/// Kept identical to the value the copies used, so a fixture keeps writing to
/// the offset it always did.
pub(crate) const KERNEL: u64 = 0xFFFF_8000_0000_0000;

/// Fold a kernel virtual address onto its offset in the image.
pub(crate) fn offset_of(address: u64) -> u64 {
    address.checked_sub(KERNEL).unwrap_or(address)
}

/// The primitive declarations the x64 kernel fixtures repeat verbatim.
///
/// Ten fixtures carry this set. Only the three that already build their ISF
/// with `format!` splice it from here: the other seven are one contiguous raw
/// literal, and substituting a single field into those would mean doubling
/// every brace in the whole JSON document, which costs far more readability
/// than the repetition does. A fixture you can read top to bottom is the point
/// of a fixture.
pub(crate) const BASE_TYPES_X64: &str = r#"{
    "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "long long": {"size": 8, "signed": true, "kind": "int", "endian": "little"},
    "unsigned long long": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
    "unsigned short": {"size": 2, "signed": false, "kind": "int", "endian": "little"},
    "unsigned char": {"size": 1, "signed": false, "kind": "int", "endian": "little"}
  }"#;

/// The primitive declarations the 32-bit fixtures repeat.
///
/// Same set as [`BASE_TYPES_X64`] with a four-byte pointer: the XP-era stages
/// need a build whose pointer width differs, which is the whole point of those
/// fixtures.
pub(crate) const BASE_TYPES_X86: &str = r#"{
    "pointer": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long long": {"size": 8, "signed": true, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
    "unsigned short": {"size": 2, "signed": false, "kind": "int", "endian": "little"},
    "unsigned char": {"size": 1, "signed": false, "kind": "int", "endian": "little"}
  }"#;

/// A hand-built image, written by address.
pub(crate) struct Image {
    pub(crate) bytes: Vec<u8>,
    size: usize,
}

impl Image {
    /// An image of `size` zero bytes.
    pub(crate) fn sized(size: usize) -> Self {
        Self {
            bytes: vec![0u8; size],
            size,
        }
    }

    /// Write `data` at `address`.
    ///
    /// # Panics
    ///
    /// If the write would run past the end. A fixture that silently truncated
    /// would leave the structure under test half-written, and the failure would
    /// surface as a wrong field value somewhere else entirely.
    pub(crate) fn write(&mut self, address: u64, data: &[u8]) {
        let at = offset_of(address) as usize;
        assert!(
            at + data.len() <= self.size,
            "the fixture writes {} byte(s) at {address:#x}, which lands at offset {at:#x} in a \
             {:#x} byte image; raise the image size rather than moving the structure",
            data.len(),
            self.size
        );
        self.bytes[at..at + data.len()].copy_from_slice(data);
    }

    pub(crate) fn put_u64(&mut self, address: u64, value: u64) {
        self.write(address, &value.to_le_bytes());
    }

    pub(crate) fn put_u32(&mut self, address: u64, value: u32) {
        self.write(address, &value.to_le_bytes());
    }

    pub(crate) fn put_u16(&mut self, address: u64, value: u16) {
        self.write(address, &value.to_le_bytes());
    }

    pub(crate) fn put_u8(&mut self, address: u64, value: u8) {
        self.write(address, &[value]);
    }

    /// A UTF-16LE string at an address, with no terminator.
    pub(crate) fn put_utf16(&mut self, address: u64, text: &str) {
        let mut bytes = Vec::new();
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        self.write(address, &bytes);
    }

    /// A big-endian `u16`, for the fields that are stored that way.
    ///
    /// Network byte order inside an otherwise little-endian structure is the
    /// mistake `netscan` exists to guard against — port 445 read the wrong way
    /// round is 48385, a legal ephemeral port that nothing downstream catches —
    /// so the fixture can write one deliberately.
    pub(crate) fn put_be_u16(&mut self, address: u64, value: u16) {
        self.write(address, &value.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_in_either_half_lands_on_the_same_offset() {
        let mut image = Image::sized(0x1000);
        image.put_u32(0x40, 0xDEAD_BEEF);
        assert_eq!(&image.bytes[0x40..0x44], &0xDEAD_BEEFu32.to_le_bytes());

        let mut kernel = Image::sized(0x1000);
        kernel.put_u32(KERNEL + 0x40, 0xDEAD_BEEF);
        assert_eq!(kernel.bytes, image.bytes, "both halves map onto one image");
    }

    #[test]
    fn a_write_past_the_end_panics_rather_than_truncating() {
        // A half-written structure surfaces as a wrong field value somewhere
        // else entirely, which is a far worse failure to debug than a panic
        // naming the fixture line.
        let result = std::panic::catch_unwind(|| {
            let mut image = Image::sized(0x100);
            image.put_u64(0xFC, 1);
        });
        assert!(result.is_err(), "the overrun must be refused");
    }

    #[test]
    fn a_port_can_be_written_in_network_order() {
        let mut image = Image::sized(0x10);
        image.put_be_u16(0, 445);
        assert_eq!(&image.bytes[0..2], &[0x01, 0xBD]);
        // The same value little-endian is 48385 — a legal ephemeral port, which
        // is why nothing downstream catches the mistake.
        assert_eq!(u16::from_le_bytes([0x01, 0xBD]), 48385);
    }
}
