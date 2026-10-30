//! Version resources: the fixed block and the string tables read out of a
//! PE's resource tree, and the four ways an image can have none.

use super::version_info::*;
use crate::image_fixture::Image;
use std::sync::Arc;

use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_memory::{MemoryLayer, PhysicalLayer};

const BASE: u64 = 0x1_0000;
const NT_OFFSET: u64 = 0x80;
const OPTIONAL_SIZE: u16 = 0xF0;
const RSRC_RVA: u32 = 0x2000;

fn layer(image: Image) -> Arc<dyn MemoryLayer> {
    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(image.bytes));
    Arc::new(PhysicalLayer::raw(source).expect("a non-empty image"))
}

/// `IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ`: an ordinary `.rsrc`.
const RSRC_CHARACTERISTICS: u32 = 0x4000_0040;

/// A PE32+ header with one `.rsrc` section and, when asked, a resource data
/// directory pointing at it.
fn put_pe(image: &mut Image, with_resource_directory: bool) {
    put_pe_with(image, with_resource_directory, RSRC_CHARACTERISTICS);
}

fn put_pe_with(image: &mut Image, with_resource_directory: bool, rsrc_characteristics: u32) {
    image.write(BASE, b"MZ");
    image.put_u32(BASE + 0x3C, NT_OFFSET as u32);
    let nt = BASE + NT_OFFSET;
    image.write(nt, b"PE\0\0");
    let file_header = nt + 4;
    image.put_u16(file_header, 0x8664);
    image.put_u16(file_header + 2, 1);
    image.put_u16(file_header + 16, OPTIONAL_SIZE);
    let optional = file_header + 20;
    image.put_u16(optional, 0x020B);
    image.put_u64(optional + 0x18, BASE);
    image.put_u32(optional + 0x20, 0x1000);
    image.put_u32(optional + 0x24, 0x200);
    image.put_u32(optional + 0x38, 0x3000);
    image.put_u32(optional + 0x3C, 0x400);
    image.put_u32(optional + 0x6C, 16);
    if with_resource_directory {
        let at = optional + 0x70 + 2 * 8;
        image.put_u32(at, RSRC_RVA);
        image.put_u32(at + 4, 0x1000);
    }
    let table = optional + u64::from(OPTIONAL_SIZE);
    image.write(table, b".rsrc\0\0\0");
    image.put_u32(table + 8, 0x1000);
    image.put_u32(table + 12, RSRC_RVA);
    image.put_u32(table + 16, 0x1000);
    image.put_u32(table + 20, 0x600);
    image.put_u32(table + 36, rsrc_characteristics);
}

/// A resource directory holding one RT_VERSION → name 1 → language 0x409
/// chain whose data entry points at `data_rva`.
fn put_resource_tree(image: &mut Image, type_id: u32, data_rva: u32, data_size: u32) {
    let root = BASE + u64::from(RSRC_RVA);
    // Level 1: one id entry.
    image.put_u16(root + 12, 0);
    image.put_u16(root + 14, 1);
    image.put_u32(root + 16, type_id);
    image.put_u32(root + 20, 0x8000_0000 | 0x40);
    // Level 2 at +0x40: one id entry (name 1).
    let level2 = root + 0x40;
    image.put_u16(level2 + 14, 1);
    image.put_u32(level2 + 16, 1);
    image.put_u32(level2 + 20, 0x8000_0000 | 0x80);
    // Level 3 at +0x80: one language entry, pointing at a data entry at +0xC0.
    let level3 = root + 0x80;
    image.put_u16(level3 + 14, 1);
    image.put_u32(level3 + 16, 0x409);
    image.put_u32(level3 + 20, 0xC0);
    let data_entry = root + 0xC0;
    image.put_u32(data_entry, data_rva);
    image.put_u32(data_entry + 4, data_size);
}

/// A `VS_VERSIONINFO` block: the fixed info, one string table and a
/// translation block, laid out as the format prescribes.
fn version_block(file_version: [u16; 4], strings: &[(&str, &str)]) -> Vec<u8> {
    fn utf16z(s: &str) -> Vec<u8> {
        let mut v: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        v.extend_from_slice(&[0, 0]);
        v
    }
    fn pad4(v: &mut Vec<u8>) {
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
    }
    fn block(key: &str, kind: u16, value: &[u8], value_len: u16, children: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![0u8; 6];
        v.extend(utf16z(key));
        pad4(&mut v);
        v.extend_from_slice(value);
        for child in children {
            pad4(&mut v);
            v.extend_from_slice(child);
        }
        let len = v.len() as u16;
        v[0..2].copy_from_slice(&len.to_le_bytes());
        v[2..4].copy_from_slice(&value_len.to_le_bytes());
        v[4..6].copy_from_slice(&kind.to_le_bytes());
        v
    }

    let mut fixed = Vec::new();
    for word in [
        0xFEEF_04BDu32,
        0x0001_0000,
        (u32::from(file_version[0]) << 16) | u32::from(file_version[1]),
        (u32::from(file_version[2]) << 16) | u32::from(file_version[3]),
        10 << 16,
        (26200 << 16) | 1,
        0x3F,
        0,
        0x40004,
        1,
        0,
        0,
        0,
    ] {
        fixed.extend_from_slice(&word.to_le_bytes());
    }
    let string_blocks: Vec<Vec<u8>> = strings
        .iter()
        .map(|(key, value)| {
            let text = utf16z(value);
            block(key, 1, &text, (text.len() / 2) as u16, &[])
        })
        .collect();
    let table = block("040904B0", 1, &[], 0, &string_blocks);
    let string_file_info = block("StringFileInfo", 1, &[], 0, &[table]);
    let translation = block("Translation", 0, &[0x09, 0x04, 0xB0, 0x04], 4, &[]);
    let var_file_info = block("VarFileInfo", 1, &[], 0, &[translation]);
    block(
        "VS_VERSION_INFO",
        0,
        &fixed,
        52,
        &[string_file_info, var_file_info],
    )
}

fn image_with(type_id: u32, block: Option<&[u8]>, with_directory: bool) -> Image {
    let mut image = Image::sized(0x2_0000);
    put_pe(&mut image, with_directory);
    if let Some(block) = block {
        let data_rva = RSRC_RVA + 0x400;
        put_resource_tree(&mut image, type_id, data_rva, block.len() as u32);
        image.write(BASE + u64::from(data_rva), block);
    }
    image
}

/// **The fixed block and the strings are read from the resource tree**, and
/// the four-part version is the one the linker wrote.
#[test]
fn the_fixed_version_and_the_string_table_are_read_from_the_resource_tree() {
    let block = version_block(
        [10, 0, 26200, 6584],
        &[
            ("CompanyName", "Example Corp"),
            ("FileVersion", "10.0.26200.6584 (WinBuild.160101.0800)"),
            ("OriginalFilename", "example.dll"),
        ],
    );
    let image = image_with(RT_VERSION, Some(&block), true);
    let out = read_image_version(&*layer(image), BASE, &VersionInfoConfig::default());
    assert_eq!(out.outcome, VersionOutcome::Read, "{out:?}");
    let fixed = out.fixed.as_ref().expect("fixed info");
    assert_eq!(fixed.file_version, [10, 0, 26200, 6584]);
    assert_eq!(fixed.file_version_text(), "10.0.26200.6584");
    assert_eq!(fixed.product_version, [10, 0, 26200, 1]);
    assert_eq!(fixed.file_os, 0x40004);
    assert_eq!(fixed.file_type, 1);
    assert_eq!(out.strings.len(), 1);
    let table = &out.strings[0];
    assert_eq!(table.language_codepage, "040904B0");
    assert_eq!(table.get("CompanyName"), Some("Example Corp"));
    assert_eq!(table.get("OriginalFilename"), Some("example.dll"));
    assert_eq!(out.translations, vec![(0x0409, 0x04B0)]);
}

/// **An image with no resource directory** is one of the four absences, told
/// apart from an image whose resource tree holds no version.
#[test]
fn an_image_without_a_resource_directory_says_so() {
    let image = image_with(RT_VERSION, None, false);
    let out = read_image_version(&*layer(image), BASE, &VersionInfoConfig::default());
    assert_eq!(out.outcome, VersionOutcome::NoResourceDirectory);
    assert!(out.fixed.is_none());
}

/// **A resource tree without an `RT_VERSION` entry** is the second absence.
#[test]
fn a_resource_tree_without_a_version_entry_says_so() {
    let block = version_block([1, 0, 0, 0], &[]);
    let image = image_with(3, Some(&block), true);
    let out = read_image_version(&*layer(image), BASE, &VersionInfoConfig::default());
    assert_eq!(out.outcome, VersionOutcome::NoVersionResource);
}

/// **Headers that cannot be read** are the third — the ordinary case for a
/// paged-out DLL — and are never reported as an image without a version.
#[test]
fn unreadable_headers_are_reported_as_unreadable_not_as_no_version() {
    // The image ends before the base: the headers were never acquired.
    let image = Image::sized(0x100);
    let out = read_image_version(&*layer(image), BASE, &VersionInfoConfig::default());
    assert!(
        matches!(out.outcome, VersionOutcome::HeadersUnreadable(_)),
        "{:?}",
        out.outcome
    );
}

/// **A version block whose fixed signature is wrong** is malformed, and
/// nothing is read out of it as a version.
#[test]
fn a_block_with_the_wrong_fixed_signature_is_malformed_and_yields_no_version() {
    let mut block = version_block([1, 2, 3, 4], &[("CompanyName", "x")]);
    // The signature sits after the 6-byte header and the 32-byte key.
    block[40..44].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let image = image_with(RT_VERSION, Some(&block), true);
    let out = read_image_version(&*layer(image), BASE, &VersionInfoConfig::default());
    assert!(
        matches!(out.outcome, VersionOutcome::Malformed(_)),
        "{:?}",
        out.outcome
    );
    assert!(out.fixed.is_none());
}

/// **A resource section the loader marked discardable is not read at all**:
/// the kernel's own `.rsrc` on Windows 11 26200 is one, and the bytes at its
/// address after boot are something else entirely. The outcome says
/// discarded, which is neither "no version" nor "unreadable".
#[test]
fn a_discardable_resource_section_is_reported_as_discarded_and_not_read() {
    let block = version_block([1, 2, 3, 4], &[("CompanyName", "x")]);
    let mut image = Image::sized(0x2_0000);
    put_pe_with(&mut image, true, RSRC_CHARACTERISTICS | SCN_MEM_DISCARDABLE);
    let data_rva = RSRC_RVA + 0x400;
    put_resource_tree(&mut image, RT_VERSION, data_rva, block.len() as u32);
    image.write(BASE + u64::from(data_rva), &block);
    let out = read_image_version(&*layer(image), BASE, &VersionInfoConfig::default());
    assert!(
        matches!(out.outcome, VersionOutcome::ResourceDiscarded(_)),
        "{:?}",
        out.outcome
    );
    assert!(
        out.fixed.is_none(),
        "a discarded section is not decoded even if bytes are there"
    );
    assert!(out.outcome.is_discarded());
    assert!(!out.outcome.is_absence());
    assert!(!out.outcome.is_unreadable());
}
