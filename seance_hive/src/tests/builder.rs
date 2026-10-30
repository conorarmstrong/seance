//! A hive builder for the tests.
//!
//! The tests need hives with known contents, and a real hive is 20 MB of
//! somebody's machine. This writes the format's structures byte by byte from
//! the published specification, which means the tests state the layout
//! independently of the parser: if the parser and the builder ever agree on
//! something wrong, they had to agree on it twice.

use crate::hive::{BASE_BLOCK_BYTES, BIN_ALIGNMENT};

/// A value to write into a key.
pub struct TestValue {
    pub name: &'static str,
    pub data_type: u32,
    pub data: Vec<u8>,
    /// Force the "compressed name" (one byte per character) form.
    pub compressed_name: bool,
    /// Write the `0x0002 IsTombstone` flag (Windows 10 RS1+): a soft-deleted
    /// value whose `vk` cell was flagged rather than removed.
    pub tombstoned: bool,
}

impl TestValue {
    pub fn new(name: &'static str, data_type: u32, data: Vec<u8>) -> Self {
        Self {
            name,
            data_type,
            data,
            compressed_name: true,
            tombstoned: false,
        }
    }

    /// Mark this value tombstoned, as Windows 10 RS1+ writes a soft-deleted
    /// value instead of removing its cell.
    pub fn tombstoned(mut self) -> Self {
        self.tombstoned = true;
        self
    }
}

/// A key to write into the hive.
/// A security descriptor to write as an `sk` cell, and the reference count to
/// declare on it.
///
/// Descriptors are **shared**: two keys built with equal `descriptor` bytes
/// resolve to one cell, because that is what a real hive does — 117,488 keys
/// over 289 descriptors in `reference/plaso/test_data/SOFTWARE`. The count is
/// declared rather than computed so a test can write a hive that disagrees
/// with itself, which is the state a damaged or crafted hive is in.
#[derive(Clone, PartialEq, Eq)]
pub struct TestSecurity {
    pub reference_count: u32,
    pub descriptor: Vec<u8>,
}

impl TestSecurity {
    pub fn new(reference_count: u32, descriptor: Vec<u8>) -> Self {
        Self {
            reference_count,
            descriptor,
        }
    }
}

pub struct TestKey {
    pub name: &'static str,
    pub last_written: u64,
    pub values: Vec<TestValue>,
    pub subkeys: Vec<TestKey>,
    /// Force the "compressed name" form for the key's own name.
    pub compressed_name: bool,
    /// Write this subkey count into the NK instead of the number of subkeys
    /// actually written, so a hive can be made to disagree with itself — the
    /// state a damaged index or an undecremented delete leaves behind.
    pub declared_subkeys: Option<u32>,
    /// The security descriptor this key names at `nk+0x2C`. `None` writes
    /// `0xFFFFFFFF` there — no descriptor recorded, which is what every hive
    /// this builder wrote before `sk` cells were read at all.
    pub security: Option<TestSecurity>,
    /// The byte at `nk+0x0D`: the layered-key bit fields a differencing hive
    /// (minor version 6) carries — bits 0-1 layer semantics, bit 7 inherit
    /// class. Zero writes what every hive before minor 6 holds there.
    pub layer_bits: u8,
    /// A class name, written UTF-16LE into its own cell.
    pub class_name: Option<&'static str>,
}

impl TestKey {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            last_written: 0,
            values: Vec::new(),
            subkeys: Vec::new(),
            compressed_name: true,
            declared_subkeys: None,
            security: None,
            layer_bits: 0,
            class_name: None,
        }
    }

    /// Write `bits` into the layered-key bit fields at `nk+0x0D`.
    pub fn with_layer_bits(mut self, bits: u8) -> Self {
        self.layer_bits = bits;
        self
    }

    /// Give the key a class name.
    pub fn with_class(mut self, class_name: &'static str) -> Self {
        self.class_name = Some(class_name);
        self
    }

    /// Name a security descriptor from this key. Keys given equal descriptor
    /// bytes share one cell.
    pub fn with_security(mut self, security: TestSecurity) -> Self {
        self.security = Some(security);
        self
    }

    /// Declare a subkey count that does not match the index written.
    pub fn declaring_subkeys(mut self, count: u32) -> Self {
        self.declared_subkeys = Some(count);
        self
    }

    pub fn with_time(mut self, filetime: u64) -> Self {
        self.last_written = filetime;
        self
    }

    pub fn with_value(mut self, value: TestValue) -> Self {
        self.values.push(value);
        self
    }

    pub fn with_subkey(mut self, key: TestKey) -> Self {
        self.subkeys.push(key);
        self
    }

    pub fn utf16_name(mut self) -> Self {
        self.compressed_name = false;
        self
    }
}

/// Which subkey-index form to write. A real hive uses all of them depending on
/// its version and how many subkeys a key has, and a reader that only handles
/// the common one loses keys silently.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IndexForm {
    /// `lf` — fast leaf, with a four-character name hint per entry.
    FastLeaf,
    /// `lh` — hash leaf, with a name hash per entry.
    HashLeaf,
    /// `li` — index leaf, offsets only.
    IndexLeaf,
    /// `ri` — index root, pointing at leaves. Written with one leaf per
    /// subkey, so even two subkeys exercise the indirection.
    IndexRoot,
}

/// Builds a hive image in memory.
pub struct HiveBuilder {
    data: Vec<u8>,
    index_form: IndexForm,
    minor_version: u32,
    /// Descriptors written so far, in write order: `(bytes, cell offset)`.
    /// Looked up by bytes so that two keys with the same descriptor name the
    /// same cell, and kept in order so the ring can be linked in that order
    /// once every key has been written.
    security_cells: Vec<(Vec<u8>, u32)>,
}

impl HiveBuilder {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            index_form: IndexForm::HashLeaf,
            minor_version: 5,
            security_cells: Vec::new(),
        }
    }

    /// Write `minor` into the base block's minor-version field. Minor 6 is a
    /// differencing hive, the only kind whose layered-key bits mean anything.
    pub fn minor_version(mut self, minor: u32) -> Self {
        self.minor_version = minor;
        self
    }

    pub fn index_form(mut self, form: IndexForm) -> Self {
        self.index_form = form;
        self
    }

    /// Allocate a cell holding `payload` and return its offset within the
    /// hive-bin data.
    fn alloc(&mut self, payload: &[u8]) -> u32 {
        let unaligned = payload.len() + 4;
        let size = unaligned.div_ceil(8) * 8;
        let offset = self.data.len() as u32;
        self.data.extend_from_slice(&(-(size as i32)).to_le_bytes());
        self.data.extend_from_slice(payload);
        self.data.resize(offset as usize + size, 0);
        offset
    }

    /// Allocate (or reuse) the `sk` cell for `security` and return its offset.
    ///
    /// `flink` and `blink` are left zero here and filled in by [`Self::link_security_ring`]
    /// once every key has been written, because a ring cannot be closed until
    /// its last member exists.
    fn write_security(&mut self, security: &TestSecurity) -> u32 {
        if let Some((_, offset)) = self
            .security_cells
            .iter()
            .find(|(bytes, _)| *bytes == security.descriptor)
        {
            return *offset;
        }
        let mut sk = vec![0u8; 0x14 + security.descriptor.len()];
        sk[0..2].copy_from_slice(b"sk");
        sk[0x0C..0x10].copy_from_slice(&security.reference_count.to_le_bytes());
        sk[0x10..0x14].copy_from_slice(&(security.descriptor.len() as u32).to_le_bytes());
        sk[0x14..].copy_from_slice(&security.descriptor);
        let offset = self.alloc(&sk);
        self.security_cells
            .push((security.descriptor.clone(), offset));
        offset
    }

    /// Close the `sk` ring through `flink` and `blink`, as every real hive
    /// does: all twelve under `reference/plaso/test_data/` close through both
    /// with identical membership.
    fn link_security_ring(&mut self) {
        let offsets: Vec<u32> = self.security_cells.iter().map(|(_, o)| *o).collect();
        let n = offsets.len();
        for (i, offset) in offsets.iter().enumerate() {
            let flink = offsets[(i + 1) % n];
            let blink = offsets[(i + n - 1) % n];
            let base = *offset as usize + 4; // past the cell's size field
            self.data[base + 0x04..base + 0x08].copy_from_slice(&flink.to_le_bytes());
            self.data[base + 0x08..base + 0x0C].copy_from_slice(&blink.to_le_bytes());
        }
    }

    fn write_value(&mut self, value: &TestValue) -> u32 {
        // The data cell first: a value points at its data, never the reverse.
        let inline = value.data.len() <= 4;
        let (data_offset, data_size_field) = if inline {
            let mut inline_bytes = [0u8; 4];
            inline_bytes[..value.data.len()].copy_from_slice(&value.data);
            (
                u32::from_le_bytes(inline_bytes),
                value.data.len() as u32 | 0x8000_0000,
            )
        } else {
            let offset = self.alloc(&value.data);
            (offset, value.data.len() as u32)
        };

        let name_bytes: Vec<u8> = if value.compressed_name {
            value.name.bytes().collect()
        } else {
            value
                .name
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect()
        };

        let mut vk = vec![0u8; 0x14 + name_bytes.len()];
        vk[0..2].copy_from_slice(b"vk");
        vk[2..4].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        vk[4..8].copy_from_slice(&data_size_field.to_le_bytes());
        vk[8..12].copy_from_slice(&data_offset.to_le_bytes());
        vk[12..16].copy_from_slice(&value.data_type.to_le_bytes());
        let mut flags: u16 = if value.compressed_name { 0x0001 } else { 0 };
        if value.tombstoned {
            flags |= 0x0002;
        }
        vk[16..18].copy_from_slice(&flags.to_le_bytes());
        vk[0x14..].copy_from_slice(&name_bytes);
        self.alloc(&vk)
    }

    /// A value whose data is larger than one cell can hold, written as a `db`
    /// big-data record over `segment_size`-byte segments.
    pub fn write_big_value(&mut self, name: &'static str, data: &[u8], segment_size: usize) -> u32 {
        let mut segment_offsets = Vec::new();
        for chunk in data.chunks(segment_size) {
            segment_offsets.push(self.alloc(chunk));
        }
        let mut list = Vec::new();
        for offset in &segment_offsets {
            list.extend_from_slice(&offset.to_le_bytes());
        }
        let list_offset = self.alloc(&list);

        let mut db = vec![0u8; 8];
        db[0..2].copy_from_slice(b"db");
        db[2..4].copy_from_slice(&(segment_offsets.len() as u16).to_le_bytes());
        db[4..8].copy_from_slice(&list_offset.to_le_bytes());
        let db_offset = self.alloc(&db);

        let name_bytes: Vec<u8> = name.bytes().collect();
        let mut vk = vec![0u8; 0x14 + name_bytes.len()];
        vk[0..2].copy_from_slice(b"vk");
        vk[2..4].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        vk[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
        vk[8..12].copy_from_slice(&db_offset.to_le_bytes());
        vk[12..16].copy_from_slice(&3u32.to_le_bytes()); // REG_BINARY
        vk[16..18].copy_from_slice(&1u16.to_le_bytes());
        vk[0x14..].copy_from_slice(&name_bytes);
        self.alloc(&vk)
    }

    fn write_subkey_index(&mut self, children: &[u32], names: &[&str]) -> u32 {
        match self.index_form {
            IndexForm::IndexRoot => {
                // One single-entry `li` leaf per child, then an `ri` over them:
                // the indirection a large key really uses.
                let mut leaves = Vec::new();
                for child in children {
                    let mut li = vec![0u8; 4 + 4];
                    li[0..2].copy_from_slice(b"li");
                    li[2..4].copy_from_slice(&1u16.to_le_bytes());
                    li[4..8].copy_from_slice(&child.to_le_bytes());
                    leaves.push(self.alloc(&li));
                }
                let mut ri = vec![0u8; 4 + 4 * leaves.len()];
                ri[0..2].copy_from_slice(b"ri");
                ri[2..4].copy_from_slice(&(leaves.len() as u16).to_le_bytes());
                for (i, leaf) in leaves.iter().enumerate() {
                    ri[4 + i * 4..8 + i * 4].copy_from_slice(&leaf.to_le_bytes());
                }
                self.alloc(&ri)
            }
            IndexForm::IndexLeaf => {
                let mut li = vec![0u8; 4 + 4 * children.len()];
                li[0..2].copy_from_slice(b"li");
                li[2..4].copy_from_slice(&(children.len() as u16).to_le_bytes());
                for (i, child) in children.iter().enumerate() {
                    li[4 + i * 4..8 + i * 4].copy_from_slice(&child.to_le_bytes());
                }
                self.alloc(&li)
            }
            form => {
                let signature: &[u8; 2] = if form == IndexForm::FastLeaf {
                    b"lf"
                } else {
                    b"lh"
                };
                let mut leaf = vec![0u8; 4 + 8 * children.len()];
                leaf[0..2].copy_from_slice(signature);
                leaf[2..4].copy_from_slice(&(children.len() as u16).to_le_bytes());
                for (i, (child, name)) in children.iter().zip(names).enumerate() {
                    let base = 4 + i * 8;
                    leaf[base..base + 4].copy_from_slice(&child.to_le_bytes());
                    let hint: Vec<u8> = name.bytes().take(4).collect();
                    let mut four = [0u8; 4];
                    four[..hint.len()].copy_from_slice(&hint);
                    leaf[base + 4..base + 8].copy_from_slice(&four);
                }
                self.alloc(&leaf)
            }
        }
    }

    fn write_key(&mut self, key: &TestKey, is_root: bool) -> u32 {
        let child_offsets: Vec<u32> = key
            .subkeys
            .iter()
            .map(|child| self.write_key(child, false))
            .collect();
        let child_names: Vec<&str> = key.subkeys.iter().map(|c| c.name).collect();
        let subkeys_offset = if child_offsets.is_empty() {
            u32::MAX
        } else {
            self.write_subkey_index(&child_offsets, &child_names)
        };

        let value_offsets: Vec<u32> = key
            .values
            .iter()
            .map(|value| self.write_value(value))
            .collect();
        let values_offset = if value_offsets.is_empty() {
            u32::MAX
        } else {
            let mut list = Vec::new();
            for offset in &value_offsets {
                list.extend_from_slice(&offset.to_le_bytes());
            }
            self.alloc(&list)
        };

        let name_bytes: Vec<u8> = if key.compressed_name {
            key.name.bytes().collect()
        } else {
            key.name.encode_utf16().flat_map(u16::to_le_bytes).collect()
        };

        let mut flags: u16 = 0;
        if key.compressed_name {
            flags |= 0x0020;
        }
        if is_root {
            flags |= 0x0004;
        }

        let class_bytes: Option<Vec<u8>> = key
            .class_name
            .map(|c| c.encode_utf16().flat_map(u16::to_le_bytes).collect());
        let class_offset = class_bytes.as_ref().map(|bytes| self.alloc(bytes));

        let mut nk = vec![0u8; 0x4C + name_bytes.len()];
        nk[0..2].copy_from_slice(b"nk");
        nk[2..4].copy_from_slice(&flags.to_le_bytes());
        nk[4..12].copy_from_slice(&key.last_written.to_le_bytes());
        nk[0x0D] = key.layer_bits;
        nk[0x10..0x14].copy_from_slice(&u32::MAX.to_le_bytes()); // parent
        let declared = key.declared_subkeys.unwrap_or(child_offsets.len() as u32);
        nk[0x14..0x18].copy_from_slice(&declared.to_le_bytes());
        nk[0x1C..0x20].copy_from_slice(&subkeys_offset.to_le_bytes());
        nk[0x20..0x24].copy_from_slice(&u32::MAX.to_le_bytes()); // volatile subkeys
        nk[0x24..0x28].copy_from_slice(&(value_offsets.len() as u32).to_le_bytes());
        nk[0x28..0x2C].copy_from_slice(&values_offset.to_le_bytes());
        let security_offset = match &key.security {
            Some(security) => self.write_security(security),
            None => u32::MAX,
        };
        nk[0x2C..0x30].copy_from_slice(&security_offset.to_le_bytes()); // security
        nk[0x30..0x34].copy_from_slice(&class_offset.unwrap_or(u32::MAX).to_le_bytes());
        nk[0x48..0x4A].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        let class_len = class_bytes.as_ref().map_or(0, Vec::len) as u16;
        nk[0x4A..0x4C].copy_from_slice(&class_len.to_le_bytes());
        nk[0x4C..].copy_from_slice(&name_bytes);
        self.alloc(&nk)
    }

    /// A hive whose root holds one value too large for a single cell.
    pub fn build_with_big_value(
        mut self,
        name: &'static str,
        data: &[u8],
        segment_size: usize,
    ) -> Vec<u8> {
        self.data.resize(0x20, 0);
        let value_offset = self.write_big_value(name, data, segment_size);
        let mut list = Vec::new();
        list.extend_from_slice(&value_offset.to_le_bytes());
        let values_offset = self.alloc(&list);

        let name_bytes: Vec<u8> = b"ROOT".to_vec();
        let mut nk = vec![0u8; 0x4C + name_bytes.len()];
        nk[0..2].copy_from_slice(b"nk");
        nk[2..4].copy_from_slice(&0x0024u16.to_le_bytes()); // comp name + root
        nk[0x10..0x14].copy_from_slice(&u32::MAX.to_le_bytes());
        nk[0x1C..0x20].copy_from_slice(&u32::MAX.to_le_bytes());
        nk[0x20..0x24].copy_from_slice(&u32::MAX.to_le_bytes());
        nk[0x24..0x28].copy_from_slice(&1u32.to_le_bytes()); // one value
        nk[0x28..0x2C].copy_from_slice(&values_offset.to_le_bytes());
        nk[0x2C..0x30].copy_from_slice(&u32::MAX.to_le_bytes());
        nk[0x30..0x34].copy_from_slice(&u32::MAX.to_le_bytes());
        nk[0x48..0x4A].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        nk[0x4C..].copy_from_slice(&name_bytes);
        let root_offset = self.alloc(&nk);
        self.finish(root_offset)
    }

    /// Flip the cell at `offset` from allocated (negative size) to
    /// unallocated (positive) without touching its payload — exactly what a
    /// hive looks like the instant a cell is freed and before its bytes are
    /// overwritten or its bin's free space is coalesced.
    fn mark_unallocated(&mut self, offset: u32) {
        let base = offset as usize;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&self.data[base..base + 4]);
        let size = i32::from_le_bytes(raw);
        self.data[base..base + 4].copy_from_slice(&(-size).to_le_bytes());
    }

    /// A hive whose root has whatever live subkeys `root` names, plus one
    /// extra key written first and then "deleted" at the hive level: its
    /// cell's size field is flipped to unallocated while every other byte —
    /// name, values, timestamps — is left exactly as [`Self::write_key`]
    /// wrote it, and it is named by no live index. Returns the image and the
    /// deleted key's bin offset, so a test can check
    /// [`crate::hive::Hive::unallocated_cells`] against it.
    pub fn build_with_deleted_key(mut self, root: &TestKey, deleted: &TestKey) -> (Vec<u8>, u32) {
        self.data.resize(0x20, 0);
        let deleted_offset = self.write_key(deleted, false);
        self.mark_unallocated(deleted_offset);
        let root_offset = self.write_key(root, true);
        let image = self.finish(root_offset);
        (image, deleted_offset)
    }

    /// A hive whose bin holds one unallocated cell of raw `garbage` bytes that
    /// was never a key or value cell — the "free space that never held
    /// anything this reader recognises" case a carving walk must not mistake
    /// for a decoded structure. Returns the image and the garbage cell's bin
    /// offset.
    pub fn build_with_garbage_free_cell(
        mut self,
        root: &TestKey,
        garbage: &[u8],
    ) -> (Vec<u8>, u32) {
        self.data.resize(0x20, 0);
        let garbage_offset = self.alloc(garbage);
        self.mark_unallocated(garbage_offset);
        let root_offset = self.write_key(root, true);
        let image = self.finish(root_offset);
        (image, garbage_offset)
    }

    /// A hive whose bin holds `count` minimal (8-byte) unallocated cells with
    /// no recognisable signature, ahead of the given live `root`. For driving
    /// an unallocated-space walk past a numeric ceiling cheaply, without
    /// needing every cell to look like a key or value.
    pub fn build_with_many_empty_free_cells(mut self, root: &TestKey, count: usize) -> Vec<u8> {
        self.data.resize(0x20, 0);
        for _ in 0..count {
            let offset = self.alloc(&[]);
            self.mark_unallocated(offset);
        }
        let root_offset = self.write_key(root, true);
        self.finish(root_offset)
    }

    /// A hive whose bin holds `count` minimal **allocated** cells ahead of
    /// one deleted key and the live `root`. For checking that the walk's
    /// ceiling counts what it recovers from, not every cell it steps over.
    /// Returns the image and the deleted key's bin offset.
    pub fn build_with_many_empty_allocated_cells_then_deleted_key(
        mut self,
        root: &TestKey,
        deleted: &TestKey,
        count: usize,
    ) -> (Vec<u8>, u32) {
        self.data.resize(0x20, 0);
        for _ in 0..count {
            self.alloc(&[]);
        }
        let deleted_offset = self.write_key(deleted, false);
        self.mark_unallocated(deleted_offset);
        let root_offset = self.write_key(root, true);
        (self.finish(root_offset), deleted_offset)
    }

    /// Produce the hive image.
    pub fn build(mut self, root: &TestKey) -> Vec<u8> {
        // Leave room for the hive-bin header; cells start after it.
        self.data.resize(0x20, 0);
        let root_offset = self.write_key(root, true);
        self.finish(root_offset)
    }

    /// Close out the security ring, pad the bin to a page and write the base
    /// block naming `root_offset` as the root cell. Shared by every `build*`
    /// entry point so each only has to write its own cells first.
    fn finish(mut self, root_offset: u32) -> Vec<u8> {
        if !self.security_cells.is_empty() {
            self.link_security_ring();
        }

        // One bin covering everything, padded to a page.
        let bin_size = self.data.len().max(BIN_ALIGNMENT).div_ceil(BIN_ALIGNMENT) * BIN_ALIGNMENT;
        self.data.resize(bin_size, 0);
        self.data[0..4].copy_from_slice(b"hbin");
        self.data[4..8].copy_from_slice(&0u32.to_le_bytes()); // this bin's offset
        self.data[8..12].copy_from_slice(&(bin_size as u32).to_le_bytes());

        let mut image = base_block(7, 7, self.minor_version, bin_size as u32);
        image[0x24..0x28].copy_from_slice(&root_offset.to_le_bytes());
        reseal(&mut image);
        image.extend_from_slice(&self.data);
        image
    }
}

/// A base block with a checksum that verifies.
pub fn base_block(primary: u32, secondary: u32, minor: u32, data_size: u32) -> Vec<u8> {
    let mut buf = vec![0u8; BASE_BLOCK_BYTES];
    buf[0..4].copy_from_slice(b"regf");
    buf[4..8].copy_from_slice(&primary.to_le_bytes());
    buf[8..12].copy_from_slice(&secondary.to_le_bytes());
    buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // major version
    buf[0x18..0x1C].copy_from_slice(&minor.to_le_bytes());
    buf[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes()); // primary hive
    buf[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // direct memory load
    buf[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes()); // root cell
    buf[0x28..0x2C].copy_from_slice(&data_size.to_le_bytes());
    buf[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // clustering factor
    reseal(&mut buf);
    buf
}

/// Recompute the base-block checksum after a test has edited a field, so that
/// only the edited field is wrong.
pub fn reseal(buf: &mut [u8]) {
    let mut sum: u32 = 0;
    for chunk in buf[..0x1FC].as_chunks::<4>().0 {
        sum ^= u32::from_le_bytes(*chunk);
    }
    let sum = match sum {
        0 => 1,
        0xFFFF_FFFF => 0xFFFF_FFFE,
        other => other,
    };
    buf[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());
}
