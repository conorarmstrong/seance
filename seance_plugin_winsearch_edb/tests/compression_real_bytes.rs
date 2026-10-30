//! The encoded `System_Search_AutoSummary` values of five real items in the
//! NIST CFReDS Data Leakage PC's `Windows.edb` (Windows 7), committed as the
//! raw column bytes libesedb returns (`tests/fixtures/README.md`).

use seance_plugin_winsearch_edb::compression::{decode_text, Decoded};

fn fixture(row: u32) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/data_leakage_autosummary_row{row}.bin",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn an_eight_bit_value_decodes_to_its_text() {
    let Decoded::Text(t) = decode_text(&fixture(2)) else {
        panic!("row 2 is the plain 8-bit form")
    };
    assert!(
        t.starts_with("Choose which programs you want Windows to use for activities"),
        "{t}"
    );
}

#[test]
fn a_run_length_value_decodes_with_its_non_latin_characters() {
    let Decoded::Text(t) = decode_text(&fixture(24)) else {
        panic!("row 24 is the run form")
    };
    assert_eq!(
        t,
        "Enjoy the classic strategy game of Chess. Play against the computer, or compete against \
         a friend. The winner is the first to capture the opponent\u{2019}s king."
    );
    let Decoded::Text(t) = decode_text(&fixture(391)) else {
        panic!("row 391 is the run form")
    };
    assert!(
        t.starts_with("Okay, I got it. I\u{2019}ll be in touch. From: iaman"),
        "{t}"
    );
    assert!(t.contains("Subject: RE: Good job, buddy."), "{t}");
}

#[test]
fn the_compressed_forms_are_reported_not_decoded_never_as_text() {
    for (row, ty) in [(388, 3u8), (453, 2u8)] {
        match decode_text(&fixture(row)) {
            Decoded::NotDecoded { type_byte, .. } => assert_eq!(type_byte, ty, "row {row}"),
            Decoded::Text(t) => panic!("row {row} decoded to {t:?}"),
        }
    }
}
