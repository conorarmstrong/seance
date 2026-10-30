//! What the ISO Base Media signature must recognise, and where it must stop.

use super::*;

/// A `ftyp` box: declared size, major brand, and any compatible brands.
fn ftyp(major: &[u8; 4], compatible: &[&[u8; 4]]) -> Vec<u8> {
    let size = 16 + compatible.len() * 4;
    let mut out = Vec::new();
    out.extend_from_slice(&(size as u32).to_be_bytes());
    out.extend_from_slice(b"ftyp");
    out.extend_from_slice(major);
    out.extend_from_slice(&[0, 0, 0x02, 0]); // minor version
    for brand in compatible {
        out.extend_from_slice(*brand);
    }
    out
}

/// A box of `size` total bytes, `type` and zero payload.
fn boxed(kind: &[u8; 4], size: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(kind);
    out.resize(size as usize, 0);
    out
}

// ── brands ─────────────────────────────────────────────────────────────────

/// **The finding this module exists for.**
///
/// `ftyp` is the ISO Base Media header, not MP4's. Labelling every one of them
/// `mp4` files an iPhone's entire camera roll — HEIC since iOS 11 — as video,
/// where an examiner filtering carved output for images will not find it.
#[test]
fn an_iphone_photograph_is_carved_as_heic_and_not_as_video() {
    let sig = IsoBaseMediaSignature;
    for major in [b"heic", b"heix", b"heim", b"heis", b"hevc", b"hevx"] {
        let init = sig
            .header_check(&ftyp(major, &[b"mif1"]), 0)
            .expect("a HEIF file has a ftyp box like any other");
        assert_eq!(
            init.extension,
            "heic",
            "brand {:?} is a HEIF still image, not an MP4",
            String::from_utf8_lossy(major)
        );
    }
}

/// AVIF may declare `mif1` as its major brand and name `avif` only in the
/// compatible list. Reading the major brand alone files it as generic HEIF.
#[test]
fn avif_is_recognised_from_the_compatible_brands_too() {
    let sig = IsoBaseMediaSignature;

    let direct = sig.header_check(&ftyp(b"avif", &[b"mif1"]), 0).unwrap();
    assert_eq!(direct.extension, "avif");

    let indirect = sig
        .header_check(&ftyp(b"mif1", &[b"mif1", b"avif"]), 0)
        .unwrap();
    assert_eq!(
        indirect.extension, "avif",
        "an AVIF declaring mif1 as its major brand must still be carved as AVIF"
    );

    // ...but a genuine codec-agnostic HEIF, with no AVIF brand, is not AVIF.
    let heif = sig
        .header_check(&ftyp(b"mif1", &[b"mif1", b"heic"]), 0)
        .unwrap();
    assert_eq!(heif.extension, "heif");
}

#[test]
fn the_other_iso_base_media_formats_get_their_own_extensions() {
    let sig = IsoBaseMediaSignature;
    for (major, want) in [
        (b"qt  ", "mov"),
        (b"M4A ", "m4a"),
        (b"M4V ", "m4v"),
        (b"crx ", "cr3"),
        (b"3gp4", "3gp"),
        (b"3g2a", "3g2"),
    ] {
        let init = sig.header_check(&ftyp(major, &[]), 0).unwrap();
        assert_eq!(
            init.extension,
            want,
            "brand {:?}",
            String::from_utf8_lossy(major)
        );
    }
}

/// An unknown brand must still be carved. Refusing what is not in the table
/// would lose real files to protect a label.
#[test]
fn an_unrecognised_brand_is_still_carved_as_mp4() {
    let sig = IsoBaseMediaSignature;
    for major in [b"isom", b"mp42", b"zzzz"] {
        let init = sig
            .header_check(&ftyp(major, &[]), 0)
            .expect("an unknown ISO Base Media file is still a file");
        assert_eq!(init.extension, "mp4");
    }
}

/// The brand list is bounded by the box's own declared size. Reading past it
/// walks into the next box and reads its bytes as brands.
#[test]
fn compatible_brands_stop_at_the_end_of_the_ftyp_box() {
    let mut buf = ftyp(b"mif1", &[b"mif1"]);
    // The next box happens to contain the four bytes "avif". Honouring the
    // declared size means it is never read as a brand.
    buf.extend_from_slice(&boxed(b"mdat", 32));
    buf[24..28].copy_from_slice(b"avif");

    let sig = IsoBaseMediaSignature;
    let init = sig.header_check(&buf, 0).unwrap();
    assert_eq!(
        init.extension, "heif",
        "a brand from OUTSIDE the ftyp box was read as if it were inside it"
    );
}

// ── header refusals ────────────────────────────────────────────────────────

#[test]
fn something_that_is_not_a_ftyp_box_is_refused() {
    let sig = IsoBaseMediaSignature;
    assert!(sig
        .header_check(&[0x00, 0x00, 0x00, 0x14, b'n', b'o', b't', b'f'], 0)
        .is_none());
    // A box that claims to be shorter than its own header is not one.
    let mut short = ftyp(b"isom", &[]);
    short[..4].copy_from_slice(&4u32.to_be_bytes());
    assert!(sig.header_check(&short, 0).is_none());
    // Truncated buffers are refused, not read past.
    assert!(sig.header_check(&[0u8; 4], 0).is_none());
    assert!(sig.header_check(&[], 0).is_none());
}

// ── the box walk ───────────────────────────────────────────────────────────

/// **The second finding.** Before the walk, `data_check` always answered
/// `Continue`, so the engine ran every carve to its 4 GiB ceiling. A 2 MiB
/// photograph came out as the photograph plus everything after it.
#[test]
fn the_walk_stops_where_the_box_chain_ends() {
    let sig = IsoBaseMediaSignature;

    let mut image = ftyp(b"heic", &[]);
    image.extend_from_slice(&boxed(b"meta", 64));
    image.extend_from_slice(&boxed(b"mdat", 128));
    let real_end = image.len() as u64;
    // Whatever was next on the disk. It is not a box.
    image.extend_from_slice(&[0xDE; 256]);

    let mut recovery = FileRecovery {
        extension: "heic".into(),
        file_size: 0,
        calculated_file_size: None,
        offset_start: 0,
        min_filesize: 16,
        extra: 0,
        extra_bytes: Vec::new(),
    };
    assert_eq!(
        sig.data_check(&image, &mut recovery),
        DataCheckResult::Stop(real_end),
        "the carve must end where the chain does, not run on into unrelated bytes"
    );
}

/// The chain is walked across blocks, because a real file is far larger than
/// the engine's block. `extra` carries the boundary between calls.
#[test]
fn the_walk_resumes_across_blocks() {
    let sig = IsoBaseMediaSignature;
    let mut recovery = FileRecovery {
        extension: "mp4".into(),
        file_size: 0,
        calculated_file_size: None,
        offset_start: 0,
        min_filesize: 16,
        extra: 0,
        extra_bytes: Vec::new(),
    };

    // Block 0: a ftyp box, then an mdat whose 1 KiB payload runs past this
    // block — the ordinary shape of any real media file.
    let mut block0 = ftyp(b"isom", &[]);
    block0.extend_from_slice(&1024u32.to_be_bytes());
    block0.extend_from_slice(b"mdat");
    block0.resize(512, 0);

    assert_eq!(
        sig.data_check(&block0, &mut recovery),
        DataCheckResult::Continue,
        "a chain that continues past the block must not be cut off there"
    );
    let ftyp_len = ftyp(b"isom", &[]).len() as u64;
    assert_eq!(
        recovery.extra,
        ftyp_len + 1024,
        "the next boundary must be carried to the following block"
    );

    // The block containing that boundary: nothing box-like there, so the file
    // ended at the boundary.
    recovery.file_size = 1024;
    let tail = vec![0xAB; 512];
    assert_eq!(
        sig.data_check(&tail, &mut recovery),
        DataCheckResult::Stop(ftyp_len + 1024)
    );
}

/// A 64-bit box declares size 1 and puts the real length after the header.
/// Treating the 1 as a length would advance by one byte and desynchronise the
/// whole walk.
#[test]
fn a_sixty_four_bit_box_is_measured_from_its_extended_size() {
    let mut large = Vec::new();
    large.extend_from_slice(&1u32.to_be_bytes());
    large.extend_from_slice(b"mdat");
    large.extend_from_slice(&(4096u64).to_be_bytes());
    assert_eq!(measure_box(&large), BoxWalk::Size(4096));

    // One that claims less than its own extended header is not a box.
    let mut absurd = large.clone();
    absurd[8..16].copy_from_slice(&8u64.to_be_bytes());
    assert_eq!(measure_box(&absurd), BoxWalk::NotABox);
    // Truncated: the extended size is not there yet — need more bytes, NOT a
    // "not a box" verdict that would end the walk early.
    assert_eq!(measure_box(&large[..12]), BoxWalk::NeedMoreBytes);
}

/// **The finding this fix exists for.** A 64-bit (size-1) box header that
/// straddles the engine's block boundary must NOT be misread as the end of the
/// chain: the walk stashes the partial header and resumes on the next block, so
/// a large MP4 whose `mdat` uses the extended size is carved whole, not
/// truncated at the box boundary.
#[test]
fn a_sixty_four_bit_box_header_straddling_a_block_is_not_cut_off() {
    let sig = IsoBaseMediaSignature;
    let mut recovery = FileRecovery {
        extension: "mp4".into(),
        file_size: 0,
        calculated_file_size: None,
        offset_start: 0,
        min_filesize: 16,
        extra: 0,
        extra_bytes: Vec::new(),
    };

    // Block 0 (16 bytes): a ftyp box, then a 64-bit mdat box header whose first
    // four bytes (the size==1 marker) land in this block but whose extended size
    // spills into the next block.
    let ftyp_box = ftyp(b"isom", &[]); // 16 bytes
    let mdat_start = ftyp_box.len() as u64; // 16
    let mdat_len = 4096u64;
    let mut mdat_hdr = Vec::new();
    mdat_hdr.extend_from_slice(&1u32.to_be_bytes());
    mdat_hdr.extend_from_slice(b"mdat");
    mdat_hdr.extend_from_slice(&mdat_len.to_be_bytes()); // 16-byte 64-bit header

    let mut block0 = ftyp_box.clone();
    block0.extend_from_slice(&mdat_hdr[..4]); // only the size==1 marker fits
    assert_eq!(block0.len(), 20);

    // A naive walk would call measure_box on 4 bytes of the mdat header, get
    // "not a box", and Stop right at mdat — cutting off the entire media payload.
    assert_eq!(
        sig.data_check(&block0, &mut recovery),
        DataCheckResult::Continue,
        "a straddling 64-bit header must not end the carve"
    );
    assert_eq!(
        recovery.extra, mdat_start,
        "the box start is carried for the resume"
    );
    assert!(
        !recovery.extra_bytes.is_empty(),
        "the partial header bytes are stashed for the next block"
    );

    // Block 1: the remaining 12 bytes of the mdat header, then its payload.
    recovery.file_size = block0.len() as u64; // 20
    let mut block1 = Vec::new();
    block1.extend_from_slice(&mdat_hdr[4..]); // the extended size arrives
    block1.resize(64, 0);
    // The header now completes: mdat runs to mdat_start + 4096, past this block,
    // so the walk continues rather than stopping short.
    assert_eq!(
        sig.data_check(&block1, &mut recovery),
        DataCheckResult::Continue
    );
    assert_eq!(
        recovery.extra,
        mdat_start + mdat_len,
        "the 64-bit box was measured from its extended size, not cut off"
    );
    assert!(recovery.extra_bytes.is_empty(), "the carry was consumed");
}

/// A size of zero means "to the end of the file". It cannot advance the walk,
/// and treating it as a length would loop forever on the same offset.
#[test]
fn a_zero_sized_box_does_not_stall_the_walk() {
    let sig = IsoBaseMediaSignature;
    let mut buf = ftyp(b"isom", &[]);
    buf.extend_from_slice(&0u32.to_be_bytes());
    buf.extend_from_slice(b"mdat");
    buf.resize(512, 0);

    let mut recovery = FileRecovery {
        extension: "mp4".into(),
        file_size: 0,
        calculated_file_size: None,
        offset_start: 0,
        min_filesize: 16,
        extra: 0,
        extra_bytes: Vec::new(),
    };
    assert_eq!(
        sig.data_check(&buf, &mut recovery),
        DataCheckResult::Continue,
        "a to-end-of-file box leaves the extent to the engine rather than looping"
    );
}

/// **What ends the walk, and why it is a list rather than a character test.**
///
/// The first version accepted any four printable characters. Trailing bytes of
/// `0x5A` spell `ZZZZ` — four alphanumeric characters — so the walk read a
/// 1.5 GB box size out of unallocated space and ran straight past the end of
/// the file it was carving.
#[test]
fn only_real_top_level_box_types_continue_the_walk() {
    for good in [b"ftyp", b"mdat", b"moov", b"uuid", b"meta", b"iloc"] {
        assert!(plausible_box_type(good), "{good:?} is a real top-level box");
    }
    for bad in [
        &b"ZZZZ"[..], // the bytes that broke the first version
        &b"AAAA"[..], // any run of one alphanumeric byte
        &b"1234"[..],
        &[0xDE, 0xAD, 0xBE, 0xEF][..],
        &[0x00, 0x00, 0x00, 0x00][..],
        &b"ab"[..],
    ] {
        assert!(
            !plausible_box_type(bad),
            "{:?} is not a top-level box type and must end the walk",
            String::from_utf8_lossy(bad)
        );
    }
}
