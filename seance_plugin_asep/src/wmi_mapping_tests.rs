//! Tests for the CIM repository page mapping (HUNT-195).
//!
//! Every fixture is a whole mapping file copied unaltered from a real
//! repository (`tests/fixtures/wmi/MANIFEST.json`). The expected values were
//! read off the same files by an independent Python decoder written from the
//! format references and recorded in `tests/fixtures/wmi/README.md`; the
//! corrupted-footer and truncated cases are the real files with bytes changed
//! in the test, which pin the refusal mechanism only.

use crate::wmi_mapping::*;

const DL1: &[u8] = include_bytes!("../tests/fixtures/wmi/dataleakage-win7-MAPPING1.MAP");
const DL2: &[u8] = include_bytes!("../tests/fixtures/wmi/dataleakage-win7-MAPPING2.MAP");
const DL3: &[u8] = include_bytes!("../tests/fixtures/wmi/dataleakage-win7-MAPPING3.MAP");
const LW1: &[u8] = include_bytes!("../tests/fixtures/wmi/lonewolf-win10-MAPPING1.MAP");
const XP: &[u8] = include_bytes!("../tests/fixtures/wmi/cfreds-xp-OBJECTS.MAP");
/// `INDEX.MAP` beside it on the same 2004 Windows XP disk (CFReDS Hacking Case, inode 11944).
const XP_INDEX: &[u8] = include_bytes!("../tests/fixtures/wmi/cfreds-xp-INDEX.MAP");
/// `MAPPING1.MAP` of a fresh Windows Server 2003 R2 SP2 x64 evaluation install (`VALIDATION.md` `WMI-8`).
const W2K3: &[u8] = include_bytes!("../tests/fixtures/wmi/w2k3-r2-sp2-x64-MAPPING1.MAP");

#[test]
fn data_leakage_active_mapping_is_the_highest_valid_sequence() {
    let parsed: Vec<_> = [DL1, DL2, DL3]
        .iter()
        .map(|b| parse_mapping(b, MappingForm::Vista))
        .collect();
    let seqs: Vec<u32> = parsed
        .iter()
        .map(|m| m.as_ref().expect("a real mapping file parses").sequence)
        .collect();
    assert_eq!(seqs, vec![26717, 26546, 26631]);
    assert_eq!(
        choose_active(&parsed),
        Some(0),
        "MAPPING1.MAP, sequence 26717"
    );

    let m = parsed[0].as_ref().unwrap();
    assert_eq!(m.form, MappingForm::Vista);
    assert_eq!(m.objects.sequence, 26717);
    assert_eq!(m.objects.physical_pages, 1806, "14,794,752 / 8192");
    assert_eq!(m.objects.logical.len(), 1715);
    assert_eq!(m.objects.free.len(), 91);
    assert_eq!(&m.objects.logical[..8], &[0, 11, 5, 3, 4, 27, 2, 1266]);
    assert_eq!(m.objects.logical[1714], 375);
    assert_eq!(&m.objects.free[..3], &[1747, 1757, 1745]);
    let index = m.index.as_ref().expect("INDEX.BTR's section follows");
    assert_eq!(index.sequence, 26717);
    assert_eq!(index.physical_pages, 551);
    assert_eq!(index.logical.len(), 328);
    assert_eq!(index.free.len(), 241);
    // Mapped and free pages partition the physical pages.
    let mut all: Vec<u32> = m
        .objects
        .logical
        .iter()
        .chain(&m.objects.free)
        .copied()
        .collect();
    all.sort_unstable();
    assert_eq!(all, (0..1806).collect::<Vec<u32>>());
}

#[test]
fn lonewolf_mapping_maps_logical_page_n_to_physical_page_m() {
    let m = parse_mapping(LW1, MappingForm::Vista).expect("parses");
    assert_eq!(m.sequence, 25064);
    assert_eq!(m.objects.physical_pages, 2928, "23,986,176 / 8192");
    assert_eq!(m.objects.logical.len(), 2774);
    assert_eq!(m.objects.free.len(), 154);
    assert_eq!(
        m.objects.physical(0),
        Some(2645),
        "logical 0 is not physical 0"
    );
    assert_eq!(&m.objects.logical[1..8], &[1, 2, 3, 4, 5, 6, 295]);
    assert_eq!(m.objects.physical(2773), Some(2877));
    assert_eq!(m.objects.physical(2774), None);
    // The class definition the scan tests reassemble: physical 42 is logical
    // 44, and logical 45 is physical 45 -- not the physically next page 43.
    let inv = m.objects.inverse(2928);
    assert_eq!(inv[42], Some(44));
    assert_eq!(m.objects.physical(45), Some(45));
    assert_eq!(inv[2713], None, "page 2713 is free");
    assert!(m.objects.free.contains(&2713));
    let index = m.index.as_ref().unwrap();
    assert_eq!(
        (index.physical_pages, index.logical.len(), index.free.len()),
        (685, 450, 246)
    );
}

#[test]
fn the_xp_objects_map_is_one_section_of_four_byte_entries() {
    let m = parse_mapping(XP, MappingForm::Xp).expect("parses");
    assert_eq!(m.form, MappingForm::Xp);
    assert_eq!(m.sequence, 4557);
    assert_eq!(m.objects.physical_pages, 667, "5,464,064 / 8192");
    assert_eq!(m.objects.logical.len(), 621);
    assert_eq!(m.objects.free.len(), 46);
    assert_eq!(&m.objects.logical[..8], &[561, 9, 0, 4, 5, 8, 622, 281]);
    assert_eq!(m.objects.logical[620], 555);
    assert!(m.index.is_none());
    // The wrong form is refused rather than misread.
    assert!(parse_mapping(XP, MappingForm::Vista).is_err());
    assert!(parse_mapping(DL1, MappingForm::Xp).is_err());
}

#[test]
fn a_mapping_file_with_a_bad_footer_is_not_chosen() {
    // MAPPING1.MAP is the newest; flip its first footer (after the objects
    // section, at byte 41,552) and the next-newest, MAPPING3.MAP, is chosen.
    let mut bad = DL1.to_vec();
    assert_eq!(&bad[41552..41556], &[0xBA, 0xDC, 0, 0]);
    bad[41552] ^= 0xFF;
    let parsed = vec![
        parse_mapping(&bad, MappingForm::Vista),
        parse_mapping(DL2, MappingForm::Vista),
        parse_mapping(DL3, MappingForm::Vista),
    ];
    let reason = parsed[0].as_ref().expect_err("a bad footer is refused");
    assert!(reason.contains("footer"), "{reason}");
    assert_eq!(choose_active(&parsed), Some(2));
    assert_eq!(choose_active(&[Err("x".into())]), None);
}

#[test]
fn a_truncated_mapping_file_is_refused_with_a_reason() {
    for cut in [0, 3, 16, 23, 24, 1000, 41552, 41555, 50000] {
        let r = parse_mapping(&DL1[..cut], MappingForm::Vista);
        assert!(r.is_err(), "cut at {cut} must be refused");
    }
    for cut in [0, 15, 100, 2687] {
        assert!(parse_mapping(&XP[..cut], MappingForm::Xp).is_err());
    }
    // A logical page count beyond the file, or a physical page past the count,
    // is refused rather than allocated or trusted.
    let mut huge = DL1.to_vec();
    huge[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse_mapping(&huge, MappingForm::Vista).is_err());
    let mut past = DL1.to_vec();
    past[24..28].copy_from_slice(&5000u32.to_le_bytes());
    let reason = parse_mapping(&past, MappingForm::Vista).unwrap_err();
    assert!(reason.contains("physical"), "{reason}");
    let mut sig = XP.to_vec();
    sig[0] = 0;
    assert!(parse_mapping(&sig, MappingForm::Xp)
        .unwrap_err()
        .contains("signature"));
}

/// Windows Server 2003's `MAPPINGn.MAP` holds two sections of XP-style four-byte entries, the data section then the
/// index section, with one sequence number. Read off the real file by an independent pass of `struct.unpack`: 694 logical
/// pages over 743 physical for `OBJECTS.DATA`, 126 over 147 for `INDEX.BTR`, sequence 0x1544, 49 and 21 free pages.
#[test]
fn a_server_2003_mapping_file_is_two_sections_of_four_byte_entries() {
    let m = parse_mapping(W2K3, MappingForm::XpNumbered).expect("parses");
    assert_eq!(m.form, MappingForm::XpNumbered);
    assert_eq!(m.sequence, 0x1544);
    assert_eq!(
        (
            m.objects.physical_pages,
            m.objects.logical.len(),
            m.objects.free.len()
        ),
        (743, 694, 49)
    );
    assert_eq!(&m.objects.logical[..6], &[0x2ba, 0x8, 0x0, 0x4, 0x5, 0x17f]);
    let index = m.index.as_ref().expect("an index section");
    assert_eq!(
        (index.physical_pages, index.logical.len(), index.free.len()),
        (147, 126, 21)
    );
    assert_eq!(&index.logical[..6], &[0x60, 0x7c, 0x3d, 0x76, 0x73, 0x6]);
    assert!(index.root_in_page_zero && !m.objects.root_in_page_zero);
    // The mapped and the free pages partition the physical pages of each section.
    for section in [&m.objects, &index.clone()] {
        let mut all: Vec<u32> = section
            .logical
            .iter()
            .copied()
            .filter(|&p| p != UNMAPPED)
            .collect();
        all.extend(&section.free);
        all.sort_unstable();
        assert_eq!(all, (0..section.physical_pages).collect::<Vec<_>>());
    }
    // The other forms refuse it rather than misread it.
    assert!(parse_mapping(W2K3, MappingForm::Vista).is_err());
    assert!(parse_mapping(DL1, MappingForm::XpNumbered).is_err());
    // A single-section file is no Server 2003 mapping, and neither are a truncated one or a differing index sequence.
    assert!(parse_mapping(XP, MappingForm::XpNumbered).is_err());
    for cut in [0, 15, 100, 1500, 3607] {
        assert!(
            parse_mapping(&W2K3[..cut], MappingForm::XpNumbered).is_err(),
            "cut {cut}"
        );
    }
    let index_at = 16 + 4 * 694 + 4 + 4 * 49 + 4;
    let mut other = W2K3.to_vec();
    other[index_at + 4] ^= 1;
    let why = parse_mapping(&other, MappingForm::XpNumbered).unwrap_err();
    assert!(why.contains("sequence"), "{why}");
}

/// Windows XP keeps its index mapping in `INDEX.MAP`, a single XP-form section of its own: 137 physical pages,
/// 105 logical, 32 free (read off the real file by an independent `struct.unpack` pass, which also showed that the
/// mapped and the free pages partition the 137 exactly), with the sequence number `OBJECTS.MAP` carries (4557).
#[test]
fn the_xp_index_map_is_a_single_section_of_its_own_with_the_data_maps_sequence() {
    let index = parse_xp_index_map(XP_INDEX).expect("parses");
    assert_eq!(
        (
            index.sequence,
            index.physical_pages,
            index.logical.len(),
            index.free.len()
        ),
        (4557, 137, 105, 32)
    );
    assert_eq!(&index.logical[..8], &[78, 22, 109, 4, 28, 2, 131, 27]);
    assert!(index.root_in_page_zero, "the root is named by index page 0");
    let mut all: Vec<u32> = index
        .logical
        .iter()
        .copied()
        .filter(|&p| p != UNMAPPED)
        .collect();
    all.extend(&index.free);
    all.sort_unstable();
    assert_eq!(all, (0..137).collect::<Vec<_>>());
    // Refused rather than misread: a truncation, a bad signature, and the data section's file.
    for cut in [0, 15, 100, 571] {
        assert!(parse_xp_index_map(&XP_INDEX[..cut]).is_err(), "cut {cut}");
    }
    let mut sig = XP_INDEX.to_vec();
    sig[0] = 0;
    assert!(parse_xp_index_map(&sig).unwrap_err().contains("signature"));
}
