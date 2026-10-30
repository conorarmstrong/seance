//! Values (`vk`), their data types, and the three places their bytes live.
//!
//! A value's data is in one of three shapes, and picking the wrong one does
//! not fail — it returns other bytes, which is the failure mode that matters
//! for a tool whose output is quoted:
//!
//! 1. **Inline.** Four bytes or fewer are stored *in* the data-offset field,
//!    flagged by the top bit of the size field.
//! 2. **One cell.** The offset names a cell holding the bytes.
//! 3. **Big data.** Past what one cell holds, the offset names a `db` record
//!    listing segments, which are concatenated in list order.
//!
//! Layout from Maxim Suhanov's *Windows registry file format specification*
//! (CC BY 4.0).

use crate::error::{HiveError, Result};
use crate::hive::Hive;
use crate::name::HiveNameString;

/// Fixed part of a value, before the name.
const VK_FIXED_BYTES: usize = 0x14;

const VK_NAME_LENGTH: usize = 0x02;
const VK_DATA_SIZE: usize = 0x04;
const VK_DATA_OFFSET: usize = 0x08;
const VK_DATA_TYPE: usize = 0x0C;
const VK_FLAGS: usize = 0x10;

/// Set in the size field when the data is stored in the offset field itself.
const DATA_IS_INLINE: u32 = 0x8000_0000;

/// The name is one byte per character rather than UTF-16LE.
const VALUE_COMP_NAME: u16 = 0x0001;

/// Set on a `vk` cell Windows 10 Anniversary Update (RS1) onward soft-deleted
/// instead of removing. Confirmed against this repo's own cross-check of the
/// specification (`docs/SPEC_CROSSCHECK.md`, "Key value (`vk`)" table).
const VALUE_IS_TOMBSTONE: u16 = 0x0002;

/// What one cell can hold of a value's data before the big-data form is used.
///
/// A cell is at most 16,344 usable bytes once its size field and the
/// allocation granularity are accounted for. Larger values are segmented.
const MAX_BYTES_IN_ONE_CELL: u32 = 16_344;

/// The registry data types.
///
/// The variant names are an interface, not an implementation detail: callers
/// format this with `Debug` and match on the text, so renaming one silently
/// changes what an examiner sees in a report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyValueDataType {
    RegNone,
    RegSZ,
    RegExpandSZ,
    RegBinary,
    RegDWord,
    RegDWordBigEndian,
    RegLink,
    RegMultiSZ,
    RegResourceList,
    RegFullResourceDescriptor,
    RegResourceRequirementsList,
    RegQWord,
    /// A type this format does not define. Reported as the number that was
    /// there, rather than folded into `RegBinary` — an examiner is entitled to
    /// know the difference between "binary" and "whatever this is".
    Unknown(u32),
}

impl KeyValueDataType {
    fn from_code(code: u32) -> Self {
        match code {
            0 => Self::RegNone,
            1 => Self::RegSZ,
            2 => Self::RegExpandSZ,
            3 => Self::RegBinary,
            4 => Self::RegDWord,
            5 => Self::RegDWordBigEndian,
            6 => Self::RegLink,
            7 => Self::RegMultiSZ,
            8 => Self::RegResourceList,
            9 => Self::RegFullResourceDescriptor,
            10 => Self::RegResourceRequirementsList,
            11 => Self::RegQWord,
            other => Self::Unknown(other),
        }
    }
}

/// A value's bytes, borrowed where they are contiguous and joined where they
/// are not.
#[derive(Clone, Debug)]
pub enum KeyValueData<'a> {
    /// The data as it sits in the hive, or in the value's own offset field.
    Slice(&'a [u8]),
    /// Reassembled from big-data segments.
    Joined(Vec<u8>),
    /// Four bytes or fewer held in the offset field.
    Inline([u8; 4], usize),
}

impl KeyValueData<'_> {
    /// The bytes, copied.
    pub fn into_vec(self) -> Result<Vec<u8>> {
        Ok(match self {
            Self::Slice(bytes) => bytes.to_vec(),
            Self::Joined(bytes) => bytes,
            Self::Inline(bytes, len) => bytes[..len].to_vec(),
        })
    }

    /// The bytes, borrowed where that is possible.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Slice(bytes) => bytes,
            Self::Joined(bytes) => bytes,
            Self::Inline(bytes, len) => &bytes[..*len],
        }
    }
}

/// One value of one key.
#[derive(Clone, Copy, Debug)]
pub struct KeyValue<'a> {
    hive: Hive<'a>,
    cell: &'a [u8],
    offset: u32,
}

impl<'a> KeyValue<'a> {
    fn from_cell_offset(hive: Hive<'a>, offset: u32) -> Result<Self> {
        let cell = hive.cell_data(offset)?;
        Self::from_cell_bytes(hive, cell, offset)
    }

    /// Parse a key value from cell contents the caller already holds, rather
    /// than looking them up by offset through [`Hive::cell_data`].
    ///
    /// See [`crate::key_node::KeyNode::from_cell_bytes`], which exists for the
    /// same reason: [`crate::unallocated::UnallocatedCells`] walks free space
    /// on purpose and needs the same field parsing without the allocation
    /// check `cell_data` insists on first.
    pub(crate) fn from_cell_bytes(hive: Hive<'a>, cell: &'a [u8], offset: u32) -> Result<Self> {
        if cell.len() < VK_FIXED_BYTES {
            return Err(HiveError::Truncated {
                structure: "key value",
                offset: VK_FIXED_BYTES,
                available: cell.len(),
            });
        }
        if &cell[..2] != b"vk" {
            return Err(HiveError::BadSignature {
                structure: "key value",
                offset: offset as usize,
                expected: "vk",
                found: [cell[0], cell[1], 0, 0],
            });
        }
        Ok(Self { hive, cell, offset })
    }

    fn u16_at(&self, at: usize) -> u16 {
        u16::from_le_bytes([self.cell[at], self.cell[at + 1]])
    }

    fn u32_at(&self, at: usize) -> u32 {
        u32::from_le_bytes([
            self.cell[at],
            self.cell[at + 1],
            self.cell[at + 2],
            self.cell[at + 3],
        ])
    }

    /// Where this value's cell starts, relative to the hive-bin data.
    pub fn cell_offset(&self) -> u32 {
        self.offset
    }

    /// The value's name. An empty name is the key's default value.
    pub fn name(&self) -> Result<HiveNameString<'a>> {
        let length = self.u16_at(VK_NAME_LENGTH) as usize;
        let end = VK_FIXED_BYTES + length;
        if end > self.cell.len() {
            return Err(HiveError::Truncated {
                structure: "value name",
                offset: end,
                available: self.cell.len(),
            });
        }
        let bytes = &self.cell[VK_FIXED_BYTES..end];
        Ok(if self.u16_at(VK_FLAGS) & VALUE_COMP_NAME != 0 {
            HiveNameString::Latin1(bytes)
        } else {
            HiveNameString::Utf16Le(bytes)
        })
    }

    /// How many bytes of data the value declares.
    pub fn data_size(&self) -> u32 {
        self.u32_at(VK_DATA_SIZE) & !DATA_IS_INLINE
    }

    pub fn data_type(&self) -> Result<KeyValueDataType> {
        Ok(KeyValueDataType::from_code(self.u32_at(VK_DATA_TYPE)))
    }

    /// Whether this value is a tombstone: a soft-delete marker Windows 10
    /// RS1+ writes over a deleted value's `vk` cell instead of freeing it.
    ///
    /// A tombstoned value is deleted-value evidence — real and worth
    /// reporting — but it is not current data. It is surfaced through the
    /// same [`KeyValues`] walk as every other value rather than filtered out
    /// or routed elsewhere, because dropping it silently would lose the
    /// evidence; callers building a "what is here now" listing must check
    /// this flag and exclude it, exactly as they must not report a value's
    /// name without also checking it decoded. See `docs/SPEC_CROSSCHECK.md`.
    pub fn is_tombstoned(&self) -> bool {
        self.u16_at(VK_FLAGS) & VALUE_IS_TOMBSTONE != 0
    }

    /// The value's bytes.
    pub fn data(&self) -> Result<KeyValueData<'a>> {
        let raw_size = self.u32_at(VK_DATA_SIZE);
        let size = (raw_size & !DATA_IS_INLINE) as usize;

        if raw_size & DATA_IS_INLINE != 0 {
            // Held in the offset field. More than four bytes cannot be, so a
            // header claiming otherwise is corrupt rather than merely odd.
            if size > 4 {
                return Err(HiveError::InvalidSizeField {
                    structure: "inline value data",
                    offset: self.offset as usize + VK_DATA_SIZE,
                    value: size as u64,
                });
            }
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&self.cell[VK_DATA_OFFSET..VK_DATA_OFFSET + 4]);
            return Ok(KeyValueData::Inline(bytes, size));
        }

        if size == 0 {
            return Ok(KeyValueData::Slice(&[]));
        }

        let data_offset = self.u32_at(VK_DATA_OFFSET);
        let cell = self.hive.cell_data(data_offset)?;

        if size as u32 > MAX_BYTES_IN_ONE_CELL && cell.len() >= 8 && &cell[..2] == b"db" {
            return self.big_data(cell, size);
        }

        if size > cell.len() {
            return Err(HiveError::Truncated {
                structure: "value data",
                offset: size,
                available: cell.len(),
            });
        }
        Ok(KeyValueData::Slice(&cell[..size]))
    }

    /// Reassemble a value stored as big data.
    ///
    /// The `db` record names a list cell of segment offsets; each segment cell
    /// holds up to [`MAX_BYTES_IN_ONE_CELL`] bytes, and they are joined in list
    /// order. Order is the whole of the correctness here: segments joined out
    /// of order produce a blob that parses and means something else.
    fn big_data(&self, db_cell: &'a [u8], size: usize) -> Result<KeyValueData<'a>> {
        let segment_count = u16::from_le_bytes([db_cell[2], db_cell[3]]) as usize;
        let list_offset = u32::from_le_bytes([db_cell[4], db_cell[5], db_cell[6], db_cell[7]]);
        let list = self.hive.cell_data(list_offset)?;
        if list.len() < segment_count * 4 {
            return Err(HiveError::Truncated {
                structure: "big-data segment list",
                offset: segment_count * 4,
                available: list.len(),
            });
        }

        let mut joined = Vec::with_capacity(size.min(1 << 24));
        for i in 0..segment_count {
            let base = i * 4;
            let segment_offset =
                u32::from_le_bytes([list[base], list[base + 1], list[base + 2], list[base + 3]]);
            let segment = self.hive.cell_data(segment_offset)?;
            let wanted = (size - joined.len()).min(MAX_BYTES_IN_ONE_CELL as usize);
            let take = wanted.min(segment.len());
            joined.extend_from_slice(&segment[..take]);
            if joined.len() >= size {
                break;
            }
        }

        if joined.len() < size {
            return Err(HiveError::Truncated {
                structure: "big-data segments",
                offset: size,
                available: joined.len(),
            });
        }
        joined.truncate(size);
        Ok(KeyValueData::Joined(joined))
    }
}

/// The values of one key, yielded one at a time.
pub struct KeyValues<'a> {
    hive: Hive<'a>,
    offsets: std::vec::IntoIter<u32>,
}

impl<'a> KeyValues<'a> {
    pub(crate) fn new(hive: Hive<'a>, list_offset: u32, count: u32) -> Result<Self> {
        let list = hive.cell_data(list_offset)?;
        let count = count as usize;
        if list.len() < count * 4 {
            return Err(HiveError::Truncated {
                structure: "key values list",
                offset: count * 4,
                available: list.len(),
            });
        }
        let offsets: Vec<u32> = (0..count)
            .map(|i| {
                let base = i * 4;
                u32::from_le_bytes([list[base], list[base + 1], list[base + 2], list[base + 3]])
            })
            .collect();
        Ok(Self {
            hive,
            offsets: offsets.into_iter(),
        })
    }
}

impl<'a> Iterator for KeyValues<'a> {
    type Item = Result<KeyValue<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.offsets.next()?;
        Some(KeyValue::from_cell_offset(self.hive, offset))
    }
}
