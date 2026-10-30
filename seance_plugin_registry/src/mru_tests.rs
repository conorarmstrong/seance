//! The shell MRU keys and outgoing RDP — stated before they were built.
//!
//! # Where the fixtures come from
//!
//! Real hives read while planning §2.5: `LoneWolf`'s `NTUSER.DAT` and
//! `NTUSER-WIN7.DAT` from the plaso corpus. Each ground-truth byte string is
//! quoted verbatim in the test that uses it.
//!
//! One family is different and the difference is stated where it matters:
//! **outgoing RDP is absent from all four real user hives on this machine**
//! (`LoneWolf` `jcloudy`, plaso `NTUSER.DAT`, `NTUSER-WIN7.DAT`,
//! `NTUSER-CCLEANER.DAT` — all checked). Its tests are synthetic, built from
//! the documented shape, and a synthetic fixture is not validation.

use super::mru::*;

// --- MRUListEx ordering ----------------------------------------------------

/// `MRUListEx` is little-endian `u32` indices, most-recent-first, terminated by
/// `0xFFFFFFFF`.
///
/// Verbatim from `LoneWolf`'s `ComDlg32\CIDSizeMRU`:
/// `00000000 01000000 02000000 04000000 03000000 ffffffff` over values named
/// `0`..`4`. Note the order: `4` is more recent than `3`.
#[test]
fn mrulistex_gives_positions_most_recent_first() {
    let bytes: Vec<u8> = [0u32, 1, 2, 4, 3, 0xFFFF_FFFF]
        .iter()
        .flat_map(|n| n.to_le_bytes())
        .collect();
    let order = parse_mrulistex(&bytes);
    assert_eq!(
        order,
        vec![0u32, 1, 2, 4, 3],
        "the terminator is not an entry, and the order is as stored"
    );
    // Position 0 is the most recent.
    assert_eq!(position_of("0", &order, OrderKind::ListEx), Some(0));
    assert_eq!(position_of("4", &order, OrderKind::ListEx), Some(3));
    assert_eq!(position_of("3", &order, OrderKind::ListEx), Some(4));
}

/// A `MRUListEx` with no terminator is read to its end rather than refused —
/// but nothing is invented past it.
#[test]
fn an_unterminated_mrulistex_is_read_to_its_end() {
    let bytes: Vec<u8> = [0u32, 1].iter().flat_map(|n| n.to_le_bytes()).collect();
    assert_eq!(parse_mrulistex(&bytes), vec![0u32, 1]);
    // A trailing partial index is not half an index.
    let mut ragged = bytes.clone();
    ragged.push(0x07);
    assert_eq!(
        parse_mrulistex(&ragged),
        vec![0u32, 1],
        "three spare bytes are not a fourth index"
    );
}

// --- MRUList ordering (RunMRU only) ----------------------------------------

/// `MRUList` is UTF-16LE letters in order, and only `RunMRU` uses it.
///
/// Verified on `NTUSER-WIN7.DAT`: `MRUList` = `a`, and value `a` is a
/// `REG_SZ` ending in the literal byte `\x01`.
#[test]
fn mrulist_gives_positions_by_letter() {
    let bytes: Vec<u8> = "acb".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let order = parse_mrulist(&bytes);
    assert_eq!(order, vec!["a", "c", "b"]);
    assert_eq!(
        position_of("a", &[], OrderKind::List(order.clone())),
        Some(0)
    );
    assert_eq!(
        position_of("c", &[], OrderKind::List(order.clone())),
        Some(1)
    );
    assert_eq!(position_of("b", &[], OrderKind::List(order)), Some(2));
}

/// The `\x01` separator `RunMRU` appends is stripped into the command.
///
/// Verified on `NTUSER-WIN7.DAT`, whose value `a` ends in that byte. Leaving it
/// in would put a control character into a command quoted in a report.
#[test]
fn the_runmru_separator_byte_is_stripped_from_the_command() {
    let stored = "\\\\controller\\WebDavShare\u{1}";
    let e = decode_runmru("a", stored);
    assert_eq!(
        e.command.as_deref(),
        Some("\\\\controller\\WebDavShare"),
        "the trailing \\x01 is a separator, not part of the command"
    );
    assert!(
        !e.command.as_deref().unwrap_or("").contains('\u{1}'),
        "no control byte may reach a report"
    );
}

// --- The two states a naive implementation gets wrong -----------------------

/// A value present but **not named** by `MRUListEx` has no position, and says
/// why.
///
/// This is a stale value left behind after the list shrank. Giving it a
/// position would assert an ordering the hive does not record; dropping it
/// would lose evidence that is present.
#[test]
fn a_value_absent_from_the_order_list_has_no_position_and_says_so() {
    let order = vec![0u32, 1];
    assert_eq!(position_of("7", &order, OrderKind::ListEx), None);
    let e = ShellMruEntry::new(MruKind::CidSizeMru, "7", None, OrderSource::NotListed);
    let j = e.to_json();
    assert!(j["mru_position"].is_null());
    assert_eq!(
        j["mru_order_source"],
        serde_json::json!("not listed in MRUListEx")
    );
    assert!(
        j["mru_order_note"].as_str().unwrap_or("").contains("stale"),
        "got {:?}",
        j["mru_order_note"]
    );
}

/// An index in `MRUListEx` naming a value that does not exist is **counted and
/// stated**, never silently skipped.
///
/// The list says there were five entries; the key holds four. That gap is a
/// fact about the hive.
#[test]
fn an_index_naming_a_missing_value_is_counted_on_the_coverage() {
    let c = MruCoverage {
        mru_kind: MruKind::CidSizeMru,
        key_path: r"ROOT\...\ComDlg32\CIDSizeMRU".into(),
        values_total: 4,
        entries: 4,
        order_indices: 5,
        indices_without_a_value: 1,
        values_not_in_order: 0,
        key_last_written: None,
    };
    let j = c.to_json();
    assert_eq!(j["indices_without_a_value"], serde_json::json!(1));
    assert!(
        j["coverage_note"]
            .as_str()
            .unwrap_or("")
            .contains("names 1 value(s) this key does not hold"),
        "got {:?}",
        j["coverage_note"]
    );
}

// --- The shell item, and what is NOT read ----------------------------------

/// A `RecentDocs` body is a UTF-16 display name, a NUL, then a shell item ID
/// list whose tail holds the `.lnk` name.
///
/// Verified on `NTUSER-WIN7.DAT`'s `.docx` subkey: `VIBRANIUM.docx`, then a
/// PIDL, then `VIBRANIUM.lnk`.
#[test]
fn a_recentdocs_body_yields_its_display_name_and_link_name() {
    let mut body: Vec<u8> = "VIBRANIUM.docx"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    body.extend_from_slice(&[0, 0]); // the NUL terminator
                                     // PIDL-ish bytes, then the NUL that terminates the field before the name.
                                     // The delimiter matters: `0x4F` is `O`, and without requiring one the scan
                                     // reads `OVIBRANIUM.lnk`. That is why `ascii_tail_ending_in` insists on it.
    body.extend_from_slice(&[0x14, 0x00, 0x1f, 0x50, 0xe0, 0x4f, 0x00]);
    body.extend_from_slice(b"VIBRANIUM.lnk\0");

    let e = decode_shell_body(MruKind::RecentDocs, "0", &body);
    assert_eq!(e.display_name.as_deref(), Some("VIBRANIUM.docx"));
    assert_eq!(e.link_name.as_deref(), Some("VIBRANIUM.lnk"));
    assert_eq!(e.extension.as_deref(), Some("docx"));
    // The delimiter-derived name now says which field to prefer, because the
    // item's own names are read from the format (`HUNT-127`).
    let basis = e.to_json()["link_name_basis"]
        .as_str()
        .expect("a basis")
        .to_string();
    assert!(basis.contains("from the delimiters and not"), "{basis}");
    assert!(basis.contains("prefer those"), "{basis}");
}

/// `HUNT-127`, `ROADMAP` §5.16. The name an examiner reads now comes out of
/// the shell item's own structure, not out of a scan for delimited printable
/// runs. The delimiter scan stays, because the `.lnk` tail it finds is a
/// different thing — the shortcut file, not the target — and its note now says
/// which to prefer.
#[test]
fn a_shell_item_id_list_yields_its_names_from_the_format() {
    let mut body: Vec<u8> = "report.docx"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    body.extend_from_slice(&[0, 0]); // the NUL that ends the display name

    // A three-level ID list: the folders the target sat in, then the target.
    for name in ["Users", "bob", "report.docx"] {
        let mut item = vec![0u8; 14];
        item[2] = 0x31; // file-entry item
        item.extend_from_slice(name.as_bytes());
        item.push(0);
        let size = item.len() as u16;
        item[0..2].copy_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&item);
    }
    body.extend_from_slice(&0u16.to_le_bytes()); // list terminator

    let j = decode_shell_body(MruKind::RecentDocs, "0", &body).to_json();
    assert_eq!(
        j["shell_item_path"],
        serde_json::json!(["Users", "bob", "report.docx"]),
        "one name per level, outermost first, each out of its own item"
    );
    assert_eq!(j["shell_item_name"], serde_json::json!("report.docx"));
    let basis = j["shell_item_path_basis"].as_str().expect("a basis");
    assert!(basis.contains("out of its structure"), "{basis}");
    assert!(
        basis.contains("UnknownType_0x"),
        "and it says what an unread level looks like: {basis}"
    );
    // This list holds no `.lnk` tail, so no weaker field is claimed at all.
    assert!(j["link_name"].is_null());
    assert!(j["link_name_basis"].is_null());
    // `HUNT-147`. These items carry no `BEEF0004` block, but each has a real,
    // NUL-terminated name at the file-entry's documented offset 14 — the
    // short-name field — and that is what the decoder read. A name read from
    // a documented offset is a parse, so the deepest item reports `true`;
    // this assertion pinned `false` while the flag was hardcoded rather than
    // read from the decoder. No block, so no MFT reference is claimed.
    assert_eq!(j["shell_item_parsed"], serde_json::json!(true));
    assert!(j["shell_item_mft_entry"].is_null());
    assert!(j["shell_item_mft_sequence"].is_null());
    // Every item decoded, so the record does not call its content incomplete
    // — but it does say exactly which fields were read and which were not.
    assert!(j["content_incomplete"].is_null(), "{j}");
    let scope = j["shell_item_decode_scope"].as_str().expect("a scope");
    assert!(scope.contains("MFT"), "{scope}");
    assert!(scope.contains("not read"), "{scope}");
}

/// `HUNT-147`. The MFT file reference a version-7+ `BEEF0004` block carries
/// reaches the record, with the same field names `seance_plugin_lnk`
/// publishes so one viewer reads both.
#[test]
fn a_file_entry_item_with_a_beef0004_block_publishes_its_mft_reference() {
    let mut body: Vec<u8> = "photo.jpg"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    body.extend_from_slice(&[0, 0]);
    let mut item = vec![0u8; 14];
    item[2] = 0x31;
    let mut block = seance_shell_item::fixture::build_beef0004(8, "photo.jpg");
    seance_shell_item::fixture::set_mft_reference(&mut block, 0x0000_ABCD_EF01, 7);
    item.extend_from_slice(&block);
    let size = item.len() as u16;
    item[0..2].copy_from_slice(&size.to_le_bytes());
    body.extend_from_slice(&item);
    body.extend_from_slice(&0u16.to_le_bytes());

    let e = decode_shell_body(MruKind::RecentDocs, "0", &body);
    assert!(e.shell_item_parsed);
    assert_eq!(e.shell_item_mft_entry, Some(0x0000_ABCD_EF01));
    assert_eq!(e.shell_item_mft_sequence, Some(7));
    let j = e.to_json();
    assert_eq!(j["shell_item_parsed"], serde_json::json!(true));
    assert_eq!(
        j["shell_item_mft_entry"],
        serde_json::json!(0x0000_ABCD_EF01u64)
    );
    assert_eq!(j["shell_item_mft_sequence"], serde_json::json!(7));
    assert_eq!(j["shell_item_name"], serde_json::json!("photo.jpg"));
}

/// `HUNT-147`. A `BEEF0004` block whose file-reference field is all zero is
/// what Windows 7 writes for every `RecentDocs` `.lnk` in `NTUSER-WIN7.DAT`
/// (38 of 38, checked by hand while wiring this in). Zero is not a reference
/// — entry 0 is `$MFT`, and no sequence number is ever 0 — so the record must
/// not claim one; it says the field was zero instead.
#[test]
fn a_zero_file_reference_in_the_block_is_not_published_as_an_mft_reference() {
    let mut body: Vec<u8> = "VIBRANIUM.lnk"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    body.extend_from_slice(&[0, 0]);
    let mut item = vec![0u8; 14];
    item[2] = 0x32;
    item.extend_from_slice(&seance_shell_item::fixture::build_beef0004(
        8,
        "VIBRANIUM.lnk",
    ));
    let size = item.len() as u16;
    item[0..2].copy_from_slice(&size.to_le_bytes());
    body.extend_from_slice(&item);
    body.extend_from_slice(&0u16.to_le_bytes());

    let e = decode_shell_body(MruKind::RecentDocs, "0", &body);
    assert!(e.shell_item_parsed);
    assert_eq!(e.shell_item_mft_entry, None);
    assert_eq!(e.shell_item_mft_sequence, None);
    let j = e.to_json();
    assert!(j["shell_item_mft_entry"].is_null());
    assert!(j["shell_item_mft_sequence"].is_null());
    let note = j["shell_item_mft_reference_note"]
        .as_str()
        .expect("the zero field is stated, not silently dropped");
    assert!(note.contains("zero"), "{note}");
}

/// An `OpenSavePidlMRU\<ext>` value is a shell item ID list and **nothing
/// before it** (plaso: `mrulistex_shell_item_list`; `LastVisitedPidlMRU` and
/// `RecentDocs` are the ones with a name first). Reading it as name-then-list
/// took the first 24 bytes — a GUID item and 4 bytes of the next — as a
/// UTF-16 "display name" of mojibake, and walked the list from 4 bytes into
/// its second item, where a `0xBB` byte was read as a file entry named `E`.
///
/// The bytes are `…\OpenSavePidlMRU\exe` value `0` of plaso's
/// `NTUSER-WIN7.DAT` (see `seance_shell_item::real_items`), which plaso reads
/// as `<Computers and Devices> <Users property view>\\controller\WebDavShare
/// \Firefox Setup 3.6.12.exe`.
#[test]
fn an_open_save_pidl_mru_value_is_a_bare_id_list_with_no_display_name() {
    let value = seance_shell_item::real_items::open_save_pidl_mru_exe_0();
    let e = decode_pidl_body(MruKind::OpenSavePidlMru, "0", &value);
    assert_eq!(
        e.display_name, None,
        "there is no name in front of the list"
    );
    assert_eq!(e.shell_item_bytes.as_deref(), Some(value.as_slice()));
    let j = e.to_json();
    assert!(j["display_name"].is_null());
    assert_eq!(
        j["shell_item_path"],
        serde_json::json!([
            "NetworkPlaces",
            "UsersPropertyView",
            "\\\\controller\\WebDavShare",
            "Firefox Setup 3.6.12.exe"
        ])
    );
    assert_eq!(j["shell_item_name"], "Firefox Setup 3.6.12.exe");
    assert_eq!(j["shell_items_total"], 4);
    // The users-property-view item is named by class and not decoded.
    assert_eq!(j["shell_items_unread"], 1);
    assert_eq!(j["content_incomplete"], true);
    assert!(j["content_incomplete_detail"]
        .as_str()
        .unwrap()
        .contains("1 of 4"));
    // The deepest item: read from its fields, v8 block, zero reference.
    assert_eq!(j["shell_item_parsed"], true);
    assert!(j["shell_item_mft_entry"].is_null());
    assert!(j["shell_item_mft_reference_note"].is_string());
    assert_eq!(j["shell_item_bytes_len"], 390);
}

/// Through `emit`: a Vista+ `OpenSavePidlMRU\exe` value (`REG_BINARY`) is
/// walked as a bare list, and an XP `OpenSaveMRU\exe` value (`REG_SZ`, a
/// path) is read as the string it is — neither as name-then-list.
#[test]
fn open_save_values_are_read_by_their_type_a_pidl_or_an_xp_path() {
    use crate::resident::{Anchor, ResidentCapture};
    use seance_hive::KeyValueDataType;

    let base = r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32";
    let pidl_key = format!(r"{base}\OpenSavePidlMRU\exe");
    let xp_key = format!(r"{base}\OpenSaveMRU\exe");
    let mut cap = ResidentCapture::default();
    let i = cap
        .begin_key(
            &pidl_key,
            Anchor::Mru {
                kind: MruKind::OpenSavePidlMru,
            },
            0,
        )
        .unwrap();
    cap.push_value(
        i,
        "0",
        Some(KeyValueDataType::RegBinary),
        &seance_shell_item::real_items::open_save_pidl_mru_exe_0(),
    );
    cap.push_value(
        i,
        "MRUListEx",
        Some(KeyValueDataType::RegBinary),
        &[0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF],
    );
    let i = cap
        .begin_key(
            &xp_key,
            Anchor::Mru {
                kind: MruKind::OpenSavePidlMru,
            },
            0,
        )
        .unwrap();
    let mut path: Vec<u8> = r"C:\Tools\setup.exe"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    path.extend_from_slice(&[0, 0]);
    cap.push_value(i, "a", Some(KeyValueDataType::RegSZ), &path);
    cap.push_value(
        i,
        "MRUList",
        Some(KeyValueDataType::RegSZ),
        &[b'a', 0, 0, 0],
    );

    let out = emit(&cap);
    let entries: Vec<_> = out
        .iter()
        .filter(|r| r["type"] == "ShellMruEntry")
        .collect();
    assert_eq!(entries.len(), 2);

    let pidl = entries.iter().find(|e| e["key_path"] == pidl_key).unwrap();
    assert!(pidl["display_name"].is_null());
    assert_eq!(pidl["shell_item_name"], "Firefox Setup 3.6.12.exe");
    assert_eq!(pidl["shell_items_total"], 4);
    assert_eq!(pidl["mru_position"], 0);

    let xp = entries.iter().find(|e| e["key_path"] == xp_key).unwrap();
    assert_eq!(xp["display_name"], r"C:\Tools\setup.exe");
    assert!(xp["shell_item_bytes_len"].is_null());
    assert!(xp["shell_item_path"].is_null());
    assert!(xp["content_incomplete"].is_null(), "{xp}");
}

/// `HUNT-147`. `parsed` is per item. A list whose deepest item decoded but
/// whose middle item is of a type this build does not know is not a complete
/// decode, and the record says how many of its items were not read.
#[test]
fn a_list_with_an_unread_item_is_disclosed_as_incomplete_with_the_count() {
    let mut body: Vec<u8> = "report.docx"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    body.extend_from_slice(&[0, 0]);
    for (name, type_byte) in [("Users", 0x31u8), ("??", 0x99), ("report.docx", 0x31)] {
        let mut item = vec![0u8; 14];
        item[2] = type_byte;
        item.extend_from_slice(name.as_bytes());
        item.push(0);
        let size = item.len() as u16;
        item[0..2].copy_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&item);
    }
    body.extend_from_slice(&0u16.to_le_bytes());

    let j = decode_shell_body(MruKind::RecentDocs, "0", &body).to_json();
    assert_eq!(
        j["shell_item_path"],
        serde_json::json!(["Users", "UnknownType_0x99", "report.docx"])
    );
    // The deepest item was read, and the flag is about that item.
    assert_eq!(j["shell_item_parsed"], serde_json::json!(true));
    assert_eq!(j["shell_items_total"], serde_json::json!(3));
    assert_eq!(j["shell_items_unread"], serde_json::json!(1));
    assert_eq!(j["content_incomplete"], serde_json::json!(true));
    assert_eq!(
        j["content_incomplete_reason"],
        serde_json::json!("unresolved_structure")
    );
    let detail = j["content_incomplete_detail"].as_str().unwrap_or("");
    assert!(detail.contains("1 of 3"), "{detail:?}");
}

/// And the deepest item's FAT times, which the MRU key's own date cannot give:
/// an MRU entry has no time of its own.
#[test]
fn the_deepest_shell_items_fat_times_reach_the_record_marked_local() {
    let mut body: Vec<u8> = "photo.jpg"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&seance_shell_item::fixture::file_entry_with_times(
        8,
        "photo.jpg",
    ));
    body.extend_from_slice(&0u16.to_le_bytes());

    let j = decode_shell_body(MruKind::RecentDocs, "0", &body).to_json();
    assert_eq!(
        j["shell_item_modified"],
        serde_json::json!("2021-06-15T14:30:44+00:00")
    );
    assert_eq!(
        j["shell_item_created"],
        serde_json::json!("2019-01-02T03:04:06+00:00")
    );
    assert_eq!(
        j["shell_item_accessed"],
        serde_json::json!("2021-12-31T23:59:58+00:00")
    );
    // Whose times they are, and that they carry no zone.
    assert_eq!(
        j["shell_item_time_scope"],
        serde_json::json!("the deepest shell item")
    );
    assert_eq!(j["timezone"], serde_json::json!("local"));
    assert!(j["shell_item_time_note"]
        .as_str()
        .expect("a note")
        .contains("they are NOT UTC"));
}

/// **A shell item that could not be walked is disclosed with what is in the
/// bytes that were not read.**
///
/// Since `ROADMAP` §5.16 the items' names, FAT times and (`HUNT-147`) MFT
/// reference are read through `seance_shell_item`. This fixture's ID list is
/// one item declaring 20 bytes (`0x14`) of which six are present, so the walk
/// yields no item at all and nothing was decoded: `shell_item_parsed` is
/// `false` because there was no item to parse, not because the flag is a
/// default, and the bytes are published whole. A record showing only
/// "VIBRANIUM.docx" with nothing said would read as all the hive held.
#[test]
fn the_unparsed_shell_item_is_disclosed_with_what_is_in_it() {
    let mut body: Vec<u8> = "VIBRANIUM.docx"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&[0x14, 0x00, 0x1f, 0x50, 0xe0, 0x4f]);

    let j = decode_shell_body(MruKind::RecentDocs, "0", &body).to_json();
    assert_eq!(j["shell_item_parsed"], serde_json::json!(false));
    assert_eq!(j["shell_items_total"], serde_json::json!(0));
    assert!(
        j["shell_item_bytes_len"].as_u64().unwrap_or(0) > 0,
        "the length of what was not read must be stated"
    );
    assert!(
        j["shell_item_bytes_base64"].is_string(),
        "and the bytes themselves kept, so a later build can decode them"
    );
    assert_eq!(
        j["content_incomplete_reason"],
        serde_json::json!("unresolved_structure")
    );
    let detail = j["content_incomplete_detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("folder chain") && detail.contains("MFT"),
        "the record must name what is in the bytes it did not read: {detail:?}"
    );
}

/// A body with no NUL terminator yields no display name rather than reading
/// the whole blob as text.
#[test]
fn a_body_without_a_terminator_does_not_read_the_pidl_as_text() {
    let body: Vec<u8> = vec![0x14, 0x00, 0x1f, 0x50, 0xe0, 0x4f, 0x11, 0x22];
    let e = decode_shell_body(MruKind::LastVisitedPidlMru, "0", &body);
    assert!(
        e.display_name.is_none() || e.display_name.as_deref() == Some(""),
        "got {:?}",
        e.display_name
    );
    // Eight bytes of a list whose one item declares twenty: the walk yields
    // nothing, so nothing was parsed (`HUNT-147` re-checked this fixture
    // against the real decoder rather than against a hardcoded flag).
    assert!(!e.shell_item_parsed);
    assert_eq!(e.shell_items_total, 0);
}

// --- TypedPaths ------------------------------------------------------------

/// `TypedPaths` is a path typed into Explorer's address bar, and is **not**
/// Internet Explorer's `TypedURLs`.
///
/// The two are separate keys with separate meanings, and `TypedURLs` is already
/// normalised into browser-history records elsewhere. Merging them would put a
/// filesystem path into a browsing history.
#[test]
fn typed_paths_are_kept_apart_from_internet_explorer_typed_urls() {
    let a = mru_kind_of(r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths");
    assert_eq!(a, Some(MruKind::TypedPaths));
    let b = mru_kind_of(r"ROOT\Software\Microsoft\Internet Explorer\TypedURLs");
    assert_eq!(
        b, None,
        "IE's TypedURLs is handled elsewhere and must not be swept in here"
    );
}

// --- Anchoring -------------------------------------------------------------

/// Every MRU family this build reads, including the XP spellings.
#[test]
fn every_mru_family_is_recognised_including_the_xp_spellings() {
    let base = r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer";
    for (path, kind) in [
        (format!(r"{base}\RecentDocs"), MruKind::RecentDocs),
        (format!(r"{base}\RecentDocs\.docx"), MruKind::RecentDocs),
        (format!(r"{base}\RecentDocs\Folder"), MruKind::RecentDocs),
        (format!(r"{base}\RunMRU"), MruKind::RunMru),
        (format!(r"{base}\TypedPaths"), MruKind::TypedPaths),
        (
            format!(r"{base}\ComDlg32\OpenSavePidlMRU\docx"),
            MruKind::OpenSavePidlMru,
        ),
        (
            format!(r"{base}\ComDlg32\LastVisitedPidlMRU"),
            MruKind::LastVisitedPidlMru,
        ),
        (format!(r"{base}\ComDlg32\CIDSizeMRU"), MruKind::CidSizeMru),
        (
            format!(r"{base}\ComDlg32\FirstFolder"),
            MruKind::FirstFolder,
        ),
        // The XP spellings, which drop the `l`.
        (
            format!(r"{base}\ComDlg32\OpenSaveMRU\doc"),
            MruKind::OpenSavePidlMru,
        ),
        (
            format!(r"{base}\ComDlg32\LastVisitedMRU"),
            MruKind::LastVisitedPidlMru,
        ),
    ] {
        assert_eq!(mru_kind_of(&path), Some(kind), "for {path}");
    }
}

/// **The roadmap misspells one of these.** It says `OpenSavePidMRU`; the key
/// Windows writes is `OpenSavePidlMRU`, verified on `NTUSER-WIN7.DAT` and
/// `LoneWolf`.
///
/// A matcher built from the roadmap's spelling would find nothing on any real
/// hive and report an absence. The misspelling is not accepted — matching it
/// would be inventing a key Windows does not write.
#[test]
fn the_roadmaps_misspelling_is_not_accepted_as_a_key() {
    let base = r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer";
    assert_eq!(
        mru_kind_of(&format!(r"{base}\ComDlg32\OpenSavePidMRU\docx")),
        None,
        "OpenSavePidMRU is not a key Windows writes; accepting it would invent one"
    );
}

/// Nothing unrelated is an MRU key.
#[test]
fn an_unrelated_key_is_not_an_mru_key() {
    for p in [
        r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer",
        r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32",
        r"ROOT\Software\Microsoft\Windows\CurrentVersion\Run",
        r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx\Deeper",
    ] {
        assert_eq!(mru_kind_of(p), None, "for {p}");
    }
}

// --- Timestamps ------------------------------------------------------------

/// An MRU entry has **no time of its own**, and says so.
///
/// The key's `nk` write time is the key's. Placing it on every entry would date
/// all of them to the most recent action.
#[test]
fn an_mru_entry_states_that_its_own_time_is_not_recorded() {
    let j = ShellMruEntry::new(MruKind::RunMru, "a", Some(0), OrderSource::MruList).to_json();
    assert!(
        j["entry_time_note"]
            .as_str()
            .unwrap_or("")
            .contains("no time of its own"),
        "got {:?}",
        j["entry_time_note"]
    );
    assert!(
        j["timestamp"].is_null(),
        "an entry raises no event of its own"
    );
}

/// One timeline event per MRU **key**, naming the position-0 entry.
///
/// That is the only date the hive gives: the key was written when the
/// most-recent entry was added. Naming that entry makes the event useful
/// without attributing the time to every other one.
#[test]
fn one_event_per_key_names_the_most_recent_entry() {
    let c = MruCoverage {
        mru_kind: MruKind::RunMru,
        key_path: r"ROOT\...\RunMRU".into(),
        values_total: 3,
        entries: 2,
        order_indices: 2,
        indices_without_a_value: 0,
        values_not_in_order: 0,
        key_last_written: Some("2011-08-16T20:16:35Z".into()),
    };
    let ev = c.timeline_event(Some("cmd.exe")).expect("an event");
    assert_eq!(ev["timestamp"], "2011-08-16T20:16:35Z");
    assert_eq!(ev["timestamp_desc"], "MRU key last written");
    assert!(
        ev["short_desc"].as_str().unwrap_or("").contains("cmd.exe"),
        "the position-0 entry is named: {:?}",
        ev["short_desc"]
    );

    // No time on the key, no event. A key with no date cannot be placed.
    let undated = MruCoverage {
        key_last_written: None,
        ..c
    };
    assert!(undated.timeline_event(Some("cmd.exe")).is_none());
}

// --- Outgoing RDP: implemented, and NOT validated --------------------------

/// The outgoing-RDP destination keys, from the **documented** shape.
///
/// **This fixture is synthetic and is not validation.** `Terminal Server
/// Client` is absent from all four real user hives on this machine — `LoneWolf`
/// `jcloudy`, plaso `NTUSER.DAT`, `NTUSER-WIN7.DAT` and `NTUSER-CCLEANER.DAT`,
/// all checked while planning. So this test pins that the code does what the
/// documentation says, and nothing more: it cannot catch a documented shape
/// that real hives do not have. The known answer on real hives is
/// `real_hive_tests.rs` (`RDP-1`, 2026-09-24).
#[test]
fn the_outgoing_rdp_keys_are_recognised_from_the_documented_shape() {
    assert_eq!(
        rdp_key(r"ROOT\Software\Microsoft\Terminal Server Client\Default"),
        Some(RdpKeyKind::Default)
    );
    assert_eq!(
        rdp_key(r"ROOT\Software\Microsoft\Terminal Server Client\Servers\10.0.0.5"),
        Some(RdpKeyKind::Server {
            host: "10.0.0.5".into()
        })
    );
    assert_eq!(
        rdp_key(r"ROOT\Software\Microsoft\Terminal Server Client"),
        None
    );
}

/// A `Default` key's `MRU0..MRUn` are destinations, in order.
#[test]
fn the_default_key_yields_its_destinations_in_order() {
    let entries = decode_rdp_default(&[
        ("MRU0".to_string(), "10.0.0.5".to_string()),
        ("MRU1".to_string(), "fileserver".to_string()),
    ]);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].host, "10.0.0.5");
    assert_eq!(entries[0].mru_position, Some(0));
    assert_eq!(entries[1].mru_position, Some(1));
    // And the record says this is an OUTGOING connection attempt, which is the
    // fact people most often get backwards with this key.
    let j = entries[0].to_json();
    assert!(
        j["direction_note"]
            .as_str()
            .unwrap_or("")
            .contains("from this machine"),
        "got {:?}",
        j["direction_note"]
    );
    assert!(
        !j["connection_succeeded"].as_bool().unwrap_or(true),
        "the key records that a destination was entered, not that it connected"
    );
}

// --- End to end, on the real hives -----------------------------------------

/// The real `NTUSER-WIN7.DAT` yields MRU entries, ordered, with the shell items
/// disclosed rather than silently dropped.
#[test]
fn the_real_win7_hive_yields_ordered_mru_entries() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("NTUSER-WIN7.DAT") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("NTUSER-WIN7.DAT", bytes);

    let coverage: Vec<_> = all.iter().filter(|r| r["type"] == "MruCoverage").collect();
    let entries: Vec<_> = all
        .iter()
        .filter(|r| r["type"] == "ShellMruEntry")
        .collect();
    assert!(
        !coverage.is_empty(),
        "a real Windows 7 user hive holds MRU keys and each must be covered"
    );
    assert!(!entries.is_empty(), "and they hold entries");

    // Every coverage record's arithmetic must account for its key.
    for c in &coverage {
        let total = c["values_total"].as_u64().unwrap_or(0);
        let entries_n = c["entries"].as_u64().unwrap_or(0);
        assert!(
            entries_n <= total,
            "a key cannot yield more entries than it has values: {:?}",
            c["key_path"]
        );
    }

    // At least one entry is ordered by a real order list, or every key on this
    // hive is unordered and that itself would be worth knowing.
    let ordered = entries
        .iter()
        .filter(|e| e["mru_position"].is_u64())
        .count();
    assert!(
        ordered > 0,
        "no entry on this hive got a position; the order lists were not read"
    );

    // Every entry states whose time is whose, and none claims its own.
    for e in &entries {
        assert_eq!(e["key_last_written_scope"], "the MRU key, not this entry");
        assert!(
            e["entry_time_note"]
                .as_str()
                .unwrap_or("")
                .contains("no time of its own"),
            "for {:?}",
            e["value_name"]
        );
        assert!(e["timestamp"].is_null(), "an entry raises no event");
    }

    // `HUNT-147`: every entry with a tail says how many items the tail
    // walked into and how many of those were not read, and it claims
    // `content_incomplete` exactly when one of those numbers says so.
    // Measured on this hive, item by item, before the assertions were
    // written: 75 entries carry a shell-item tail; 28 walk but hold a
    // users-property-view item this build names and does not decode; 47
    // decode whole; none fails to walk. (Until `HUNT-167` the nine
    // `CIDSizeMRU` and two `FirstFolder` entries were walked too, and all 11
    // "did not walk" — they hold a name and no ID list. Before
    // `OpenSavePidlMRU` was read as the bare list it is, 17 did not walk and
    // 22 "walked" into a `0xEE` item — the `0x23FEBBEE` signature's first
    // byte, met four bytes into the item.)
    let with_tail: Vec<_> = entries
        .iter()
        .filter(|e| e["shell_item_bytes_len"].is_u64())
        .collect();
    assert_eq!(with_tail.len(), 75);
    assert_eq!(
        with_tail
            .iter()
            .filter(|e| e["shell_items_total"] == 0)
            .count(),
        0
    );
    assert_eq!(
        with_tail
            .iter()
            .filter(|e| e["shell_items_total"] != 0 && e["shell_items_unread"] != 0)
            .count(),
        28
    );
    assert_eq!(
        with_tail
            .iter()
            .filter(|e| e["shell_items_total"] != 0 && e["shell_items_unread"] == 0)
            .count(),
        47
    );
    for e in &with_tail {
        let total = e["shell_items_total"].as_u64().expect("total stated");
        let unread = e["shell_items_unread"].as_u64().expect("unread stated");
        assert!(unread <= total);
        let incomplete = total == 0 || unread > 0;
        assert_eq!(
            e["content_incomplete"],
            if incomplete {
                serde_json::json!(true)
            } else {
                serde_json::Value::Null
            },
            "for {:?} / {:?}",
            e["key_path"],
            e["value_name"]
        );
        if incomplete {
            assert_eq!(
                e["content_incomplete_reason"],
                serde_json::json!("unresolved_structure")
            );
            let detail = e["content_incomplete_detail"].as_str().unwrap_or("");
            assert!(
                detail.contains("MFT") || detail.contains(&format!("{unread} of {total}")),
                "the record must say what was not read: {detail:?}"
            );
        } else {
            assert!(e["shell_item_decode_scope"].is_string());
        }
        // Zero is never published as a reference.
        if let Some(entry) = e["shell_item_mft_entry"].as_u64() {
            assert!(entry != 0 || e["shell_item_mft_sequence"] != 0);
        }
    }

    // The 38 `RecentDocs` entries: one file-entry item each, naming the
    // `.lnk`, read from its documented fields, and a version-8 block whose
    // file-reference field is zero on every one — stated, not published as
    // entry 0.
    let recent: Vec<_> = with_tail
        .iter()
        .filter(|e| e["mru_kind"] == "recent_docs")
        .collect();
    assert_eq!(recent.len(), 38);
    for e in &recent {
        assert_eq!(e["shell_item_parsed"], serde_json::json!(true));
        assert_eq!(e["shell_items_total"], 1);
        let name = e["shell_item_name"].as_str().expect("a name");
        assert!(name.to_ascii_lowercase().ends_with(".lnk"), "{name}");
        assert!(e["shell_item_mft_entry"].is_null());
        assert!(e["shell_item_mft_reference_note"].is_string());
    }

    // `LastVisitedPidlMRU` value `4` walks to
    // `MyComputer\C:\Users\nfury\Documents\Alloy Research`, and the deepest
    // item's block reads `e6ad 0000 0000 2100`: entry 0xADE6, sequence 0x21.
    // Decoded by hand from the dumped bytes before this assertion was written.
    let alloy = with_tail
        .iter()
        .find(|e| e["mru_kind"] == "last_visited_pidl_mru" && e["value_name"] == "4")
        .expect("LastVisitedPidlMRU value 4");
    assert_eq!(
        alloy["shell_item_path"],
        serde_json::json!([
            "MyComputer",
            "C:\\",
            "Users",
            "nfury",
            "Documents",
            "Alloy Research"
        ])
    );
    assert_eq!(alloy["shell_item_parsed"], serde_json::json!(true));
    assert_eq!(alloy["shell_item_mft_entry"], 44518);
    assert_eq!(alloy["shell_item_mft_sequence"], 33);
    assert!(alloy["content_incomplete"].is_null());
}

/// Exactly one timeline event per MRU key, and never one per entry.
#[test]
fn the_real_hive_raises_one_event_per_mru_key_and_none_per_entry() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("NTUSER-WIN7.DAT") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("NTUSER-WIN7.DAT", bytes);

    let events: Vec<_> = all
        .iter()
        .filter(|r| r["timestamp_desc"] == "MRU key last written")
        .collect();
    let dated_keys = all
        .iter()
        .filter(|r| r["type"] == "MruCoverage" && r["key_last_written"].is_string())
        .count();
    assert_eq!(
        events.len(),
        dated_keys,
        "one event per dated key — not one per entry, which would date every entry on a key \
         to its most recent action"
    );
    assert!(dated_keys > 0, "the real keys do carry write times");
    for e in &events {
        assert!(
            e["short_desc"]
                .as_str()
                .unwrap_or("")
                .contains("not the time of any other entry"),
            "the event must say what its time does not cover: {:?}",
            e["short_desc"]
        );
    }
}

/// The "MRU key last written" event reaches the case as a `TimelineEvent`,
/// never as a `ParsedRecord` whose `type` merely says so (HUNT-166).
///
/// `MruCoverage::timeline_event` builds the event, but it travelled through
/// `mru::emit` into the resident-record list, and the resident loop in
/// `lib.rs` wrapped everything on that list as a ParsedRecord -- so the
/// timeline never saw it. One TimelineEvent per dated key, carrying the
/// hive's replay state like every other child record.
#[test]
fn the_real_hives_mru_key_last_written_events_are_emitted_as_timeline_events() {
    use seance_core::artifact::ArtifactType;

    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("NTUSER-WIN7.DAT") else {
        return;
    };
    let all = super::userassist_tests::artifacts_for_tests("NTUSER-WIN7.DAT", bytes);

    let dated_keys = all
        .iter()
        .filter(|a| {
            a.metadata["type"] == "MruCoverage" && a.metadata["key_last_written"].is_string()
        })
        .count();
    assert!(dated_keys > 0, "the real keys do carry write times");

    let mistyped: Vec<_> = all
        .iter()
        .filter(|a| {
            a.artifact_type == ArtifactType::ParsedRecord && a.metadata["type"] == "TimelineEvent"
        })
        .map(|a| a.metadata["timestamp_desc"].clone())
        .collect();
    assert!(
        mistyped.is_empty(),
        "a record built as a timeline event must be emitted as one: {mistyped:?}"
    );

    let events: Vec<_> = all
        .iter()
        .filter(|a| {
            a.artifact_type == ArtifactType::TimelineEvent
                && a.metadata["timestamp_desc"] == "MRU key last written"
        })
        .collect();
    assert_eq!(
        events.len(),
        dated_keys,
        "one TimelineEvent per dated MRU key, on the timeline"
    );
    for e in &events {
        assert!(e.metadata["timestamp"].is_string());
        assert_eq!(e.metadata["source"], "Registry");
        assert_eq!(e.metadata["hive"], "NTUSER-WIN7.DAT");
        assert!(
            e.metadata["replay"].is_object(),
            "the event carries the hive's recovery state like every other child record"
        );
    }
}

/// `TypedPaths` and IE's `TypedURLs` stay separate through the whole pipeline.
///
/// `TypedURLs` is normalised into browser-history records elsewhere in this
/// plugin, so a merge would put a filesystem path into a browsing history.
#[test]
fn typed_paths_and_typed_urls_do_not_merge_in_the_real_output() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("NTUSER-WIN7.DAT") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("NTUSER-WIN7.DAT", bytes);
    for r in all.iter().filter(|r| r["type"] == "ShellMruEntry") {
        assert_ne!(
            r["mru_kind"], "typed_urls",
            "there is no such MRU kind; IE's TypedURLs is a different artifact"
        );
    }
    // And every typed-path record is an MRU record, not a browser one.
    for r in all
        .iter()
        .filter(|r| r["mru_kind"] == "typed_paths" && r["type"] != "MruCoverage")
    {
        assert_eq!(r["type"], "ShellMruEntry");
    }
}

/// The 29 `OpenSavePidlMRU` entries on the real hive, each a bare ID list
/// (plaso: `mrulistex_shell_item_list`). Reading them as name-then-list took
/// the leading GUID item as a UTF-16 "display name" and walked the list from
/// four bytes into its second item, so `\*` value 0 and `\exe` value 0 met
/// a `0xBB` byte — the first byte of the `0x3B93AFBB` users-property-view
/// signature — which the `type & 0x70 == 0x30` class test admitted as a file
/// entry, and published the name `E` (offset 14: `45 00`) with
/// `shell_item_parsed: true`. Every item here was hand-decoded from the
/// dumped bytes (`seance_shell_item::real_items`) before the assertions were
/// written; plaso's known answers for the same values are cited there.
#[test]
fn the_real_hives_open_save_pidl_mru_entries_walk_as_bare_id_lists() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("NTUSER-WIN7.DAT") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("NTUSER-WIN7.DAT", bytes);
    let entries: Vec<_> = all
        .iter()
        .filter(|r| r["type"] == "ShellMruEntry" && r["mru_kind"] == "open_save_pidl_mru")
        .collect();
    assert_eq!(entries.len(), 29);

    let find = |suffix: &str, value: &str| {
        entries
            .iter()
            .find(|e| e["key_path"].as_str().unwrap().ends_with(suffix) && e["value_name"] == value)
            .unwrap_or_else(|| panic!("OpenSavePidlMRU{suffix} value {value}"))
    };

    for e in &entries {
        let at = format!("{:?} / {:?}", e["key_path"], e["value_name"]);
        assert!(
            e["display_name"].is_null(),
            "no name precedes the list: {at}"
        );
        let path = e["shell_item_path"].as_array().expect("a walked path");
        assert!(path.len() >= 3, "{at}");
        assert_eq!(e["shell_items_total"], path.len(), "{at}");
        for name in path {
            let name = name.as_str().unwrap();
            assert_ne!(name, "E", "a byte read as a name: {at}");
            assert!(
                !name.starts_with("UnknownType_"),
                "an item read from a misaligned offset: {name} in {at}"
            );
        }
        let unread = e["shell_items_unread"].as_u64().unwrap();
        assert_eq!(
            unread,
            path.iter().filter(|n| *n == "UsersPropertyView").count() as u64,
            "the only items this build does not read here are users property views: {at}"
        );
        if let Some(entry) = e["shell_item_mft_entry"].as_u64() {
            assert_ne!(entry, 0, "{at}");
            assert_ne!(e["shell_item_mft_sequence"], 0, "{at}");
        }
    }

    // The two entries that used to publish `E`: four items, the deepest
    // `Firefox Setup 3.6.12.exe` read from its fields, its version-8 block's
    // file-reference field zero and stated as such.
    for (suffix, value) in [("\\*", "0"), ("\\exe", "0")] {
        let e = find(suffix, value);
        assert_eq!(
            e["shell_item_path"],
            serde_json::json!([
                "NetworkPlaces",
                "UsersPropertyView",
                "\\\\controller\\WebDavShare",
                "Firefox Setup 3.6.12.exe"
            ])
        );
        assert_eq!(e["shell_item_name"], "Firefox Setup 3.6.12.exe");
        assert_eq!(e["shell_item_bytes_len"], 390);
        assert_eq!(e["shell_item_parsed"], serde_json::json!(true));
        assert_eq!(e["shell_items_unread"], 1);
        assert_eq!(e["content_incomplete"], serde_json::json!(true));
        assert!(e["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("1 of 4"));
        assert!(e["shell_item_mft_entry"].is_null());
        assert!(e["shell_item_mft_sequence"].is_null());
        assert_eq!(
            e["shell_item_mft_reference_note"],
            serde_json::json!(seance_shell_item::MFT_REFERENCE_ZERO_NOTE)
        );
    }

    // `\*` value 11 names the same folder `LastVisitedPidlMRU` value 4
    // reaches by its full path, and carries the same file reference —
    // entry 44518, sequence 33 — read from a different value's bytes.
    let alloy = find("\\*", "11");
    assert_eq!(
        alloy["shell_item_path"],
        serde_json::json!(["UsersFiles", "UsersPropertyView", "Alloy Research"])
    );
    assert_eq!(alloy["shell_item_mft_entry"], 44518);
    assert_eq!(alloy["shell_item_mft_sequence"], 33);
    assert_eq!(alloy["shell_item_modified"], "2012-03-12T20:50:00+00:00");

    // A whole decode: no users property view, every item read, and the
    // record says what a whole decode did not cover instead of claiming
    // incompleteness it cannot point at.
    let firefox_6 = find("\\exe", "1");
    assert_eq!(
        firefox_6["shell_item_path"],
        serde_json::json!([
            "MyComputer",
            "P:\\",
            "Application Tools",
            "Firefox 6.0",
            "Firefox Setup 6.0.exe"
        ])
    );
    assert_eq!(firefox_6["shell_items_unread"], 0);
    assert!(firefox_6["content_incomplete"].is_null());
    assert!(firefox_6["shell_item_decode_scope"].is_string());
    assert!(firefox_6["shell_item_mft_entry"].is_null());
    assert!(firefox_6["shell_item_mft_reference_note"].is_string());
}

// --- CIDSizeMRU and FirstFolder: a name, not a shell item (HUNT-167) ---------

/// `CIDSizeMRU` value `2` of plaso's `NTUSER-WIN7.DAT` (592 bytes):
/// `chrome.exe` in UTF-16LE, NUL-padded to a 520-byte field, then 72 bytes
/// that are not a shell item ID list. plaso reads this key as a string MRU —
/// the name alone (`mrulistex_string`). The 72 bytes are the dumped value's,
/// and the real-hive test below checks this fixture against the hive itself.
fn cidsize_mru_chrome() -> Vec<u8> {
    let mut body: Vec<u8> = "chrome.exe"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    body.resize(520, 0);
    for word in [
        0x9fu32, 0, 0x4b9, 0x35c, 0, 0, 0, 0, 0xa4, 0, 0x324, 0x200, 0, 0, 0, 0, 1, 0,
    ] {
        body.extend_from_slice(&word.to_le_bytes());
    }
    body
}

/// `FirstFolder` value `0` of the same hive, verbatim (110 bytes): the full
/// path of the program, UTF-16LE, and two NULs.
const FIRST_FOLDER_IEXPLORE_B64: &str = "QwA6AFwAUAByAG8AZwByAGEAbQAgAEYAaQBsAGUAcwAgACgAeAA4ADYAKQBcAEkAbgB0AGUAcgBuAGUAdAAgAEUAeABwAGwAbwByAGUAcgBcAGkAZQB4AHAAbABvAHIAZQAuAGUAeABlAAAAAAA=";

fn b64(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

/// A `CIDSizeMRU` entry is the program's name. The bytes after it are kept
/// and disclosed as not decoded, never walked as a shell item ID list — which
/// is what said "could not be walked as an ID list" of all nine on the real
/// hive, true of the bytes and wrong about what the value is.
#[test]
fn a_cidsize_mru_value_is_read_as_its_program_name() {
    let body = cidsize_mru_chrome();
    assert_eq!(body.len(), 592);
    let j = decode_name_body(MruKind::CidSizeMru, "2", &body).to_json();
    assert_eq!(j["display_name"], "chrome.exe");
    assert_eq!(j["extension"], "exe");
    // Not a shell item: none of its fields is claimed.
    assert!(j["shell_item_parsed"].is_null(), "{j}");
    assert!(j["shell_item_bytes_len"].is_null(), "{j}");
    assert!(j["shell_items_total"].is_null(), "{j}");
    // The bytes after the name: all of them, kept, and said to be undecoded.
    assert_eq!(j["value_tail_bytes_len"], 592 - 22);
    assert_eq!(
        b64(j["value_tail_bytes_base64"].as_str().unwrap()),
        body[22..]
    );
    assert_eq!(j["value_tail_all_zero"], false);
    assert_eq!(j["content_incomplete"], true);
    let detail = j["content_incomplete_detail"].as_str().unwrap();
    assert!(detail.contains("570 bytes"), "{detail}");
    assert!(detail.contains("not a shell item ID list"), "{detail}");
}

/// A `FirstFolder` entry on this hive is a path and two NULs: nothing follows
/// the name but zeros, so nothing is undecoded and nothing is claimed to be.
#[test]
fn a_first_folder_value_is_read_as_its_path_with_a_zero_tail_stated() {
    let body = b64(FIRST_FOLDER_IEXPLORE_B64);
    let j = decode_name_body(MruKind::FirstFolder, "0", &body).to_json();
    assert_eq!(
        j["display_name"],
        r"C:\Program Files (x86)\Internet Explorer\iexplore.exe"
    );
    assert!(j["shell_item_parsed"].is_null(), "{j}");
    assert_eq!(j["value_tail_bytes_len"], 2);
    assert_eq!(j["value_tail_all_zero"], true);
    assert!(j["content_incomplete"].is_null(), "{j}");
}

/// Through the whole parser on the real hive: the nine `CIDSizeMRU` and two
/// `FirstFolder` entries each carry a name, and none is reported as an ID list
/// that would not walk.
#[test]
fn the_real_hives_cidsize_and_first_folder_entries_carry_their_names() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("NTUSER-WIN7.DAT") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("NTUSER-WIN7.DAT", bytes);
    let of = |kind: &str| -> Vec<&serde_json::Value> {
        all.iter()
            .filter(|r| r["type"] == "ShellMruEntry" && r["mru_kind"] == kind)
            .collect()
    };
    let cid = of("cid_size_mru");
    assert_eq!(cid.len(), 9);
    // The synthetic fixture above is this hive's value `2`, byte for byte.
    let chrome = cid.iter().find(|e| e["value_name"] == "2").unwrap();
    assert_eq!(
        b64(chrome["value_tail_bytes_base64"].as_str().unwrap()),
        cidsize_mru_chrome()[22..]
    );
    let mut names: Vec<&str> = cid
        .iter()
        .map(|e| e["display_name"].as_str().expect("a name"))
        .collect();
    names.sort();
    // Read off the dumped values before this assertion was written: four
    // program names and five AppUserModel-style GUIDs.
    assert_eq!(
        names,
        vec![
            "Explorer.EXE",
            "Skype.exe",
            "chrome.exe",
            "iexplore.exe",
            "{0B8CFE96-DB69-4D33-8E3C-36EAB4F709E0}",
            "{24B5C9BB-48B5-47FF-8343-40481DBA1E2B}",
            "{427865A0-03AF-4F25-82EE-10B6CB1DED3E}",
            "{48E1ED6B-CF49-4609-B1C1-C082BFC3D0B4}",
            "{D4F85F66-003D-4127-BCE9-CAD7A57B2857}",
        ]
    );
    for e in &cid {
        assert!(e["shell_items_total"].is_null(), "{e}");
        // Every value is 592 bytes: the name, its NUL, and the tail.
        let name_units = e["display_name"].as_str().unwrap().encode_utf16().count() as u64;
        assert_eq!(
            e["value_tail_bytes_len"].as_u64().unwrap() + (name_units + 1) * 2,
            592,
            "{e}"
        );
        assert_eq!(e["content_incomplete"], true, "{e}");
    }
    let first = of("first_folder");
    assert_eq!(first.len(), 2);
    for e in &first {
        let name = e["display_name"].as_str().expect("a path");
        assert!(name.starts_with(r"C:\"), "{name}");
        assert!(name.ends_with(".exe"), "{name}");
        assert!(e["shell_items_total"].is_null(), "{e}");
        assert_eq!(e["value_tail_all_zero"], true, "{e}");
        assert!(e["content_incomplete"].is_null(), "{e}");
    }
}

/// Build a `ResidentCapture` holding a `Default` key with the given `MRUn`
/// values (when `mru` is `Some`) and one `Servers\<host>` key per `servers`
/// entry, at DC01's two real key times.
fn rdp_capture(
    mru: Option<&[(&str, &str)]>,
    servers: &[(&str, Option<&str>)],
) -> crate::resident::ResidentCapture {
    use crate::resident::{Anchor, ResidentCapture};
    use seance_hive::KeyValueDataType;

    fn sz(s: &str) -> Vec<u8> {
        let mut v: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        v.extend_from_slice(&[0, 0]);
        v
    }
    let base = r"ROOT\Software\Microsoft\Terminal Server Client";
    let mut cap = ResidentCapture::default();
    if let Some(values) = mru {
        let i = cap
            .begin_key(
                &format!(r"{base}\Default"),
                Anchor::Rdp {
                    kind: RdpKeyKind::Default,
                },
                132_449_611_339_934_009,
            )
            .unwrap();
        for (name, host) in values {
            cap.push_value(i, name, Some(KeyValueDataType::RegSZ), &sz(host));
        }
    }
    for (host, hint) in servers {
        let i = cap
            .begin_key(
                &format!(r"{base}\Servers\{host}"),
                Anchor::Rdp {
                    kind: RdpKeyKind::Server {
                        host: (*host).into(),
                    },
                },
                132_449_601_855_804_446,
            )
            .unwrap();
        if let Some(h) = hint {
            cap.push_value(i, "UsernameHint", Some(KeyValueDataType::RegSZ), &sz(h));
        }
    }
    cap
}

fn rdp_records(cap: &crate::resident::ResidentCapture) -> Vec<serde_json::Value> {
    emit(cap)
        .into_iter()
        .filter(|r| r["type"] == "RdpDestinationEntry")
        .collect()
}

const DEFAULT_SCOPE: &str = "the Terminal Server Client\\Default key, which holds every MRU \
                             destination; not this destination";
const SERVERS_SCOPE: &str = "this destination's own Servers subkey";

/// `HUNT-243`: `Default\MRU0` and `Servers\<host>` for the same host are ONE
/// destination, joined by host, carrying the MRU position, the `UsernameHint`,
/// both keys' paths and both keys' times — each time labelled with the key it
/// dates (the per-key scope `RDP-1` found, kept).
///
/// A `Servers\<host>` key belongs to one destination: its last-write time is
/// that destination's (on DC01 of DFIR Madness Case 001 it is 03:36:25, when
/// `UsernameHint` was stored, while `Default` was written at 03:52:13).
#[test]
fn an_rdp_destination_in_both_keys_is_one_record_carrying_both() {
    let cap = rdp_capture(
        Some(&[("MRU0", "DESKTOP-SDN1RPT")]),
        &[("DESKTOP-SDN1RPT", Some(r"C137\Administrator"))],
    );
    let rdp = rdp_records(&cap);
    assert_eq!(
        rdp.len(),
        1,
        "one record per destination, not per key: {rdp:#?}"
    );
    let r = &rdp[0];
    assert_eq!(r["host"], "DESKTOP-SDN1RPT");
    assert_eq!(r["mru_position"], 0);
    assert_eq!(r["mru_positions"], serde_json::json!([0]));
    assert_eq!(r["username_hint"], r"C137\Administrator");
    assert!(r["mru_key_path"]
        .as_str()
        .unwrap()
        .ends_with(r"\Terminal Server Client\Default"));
    assert!(r["servers_key_path"]
        .as_str()
        .unwrap()
        .ends_with(r"\Terminal Server Client\Servers\DESKTOP-SDN1RPT"));
    assert!(r["mru_key_last_written"]
        .as_str()
        .unwrap()
        .starts_with("2020-09-19T03:52:13.9934009"));
    assert!(r["servers_key_last_written"]
        .as_str()
        .unwrap()
        .starts_with("2020-09-19T03:36:25.5804446"));
    assert_eq!(r["mru_key_last_written_scope"], DEFAULT_SCOPE);
    assert_eq!(r["servers_key_last_written_scope"], SERVERS_SCOPE);
    assert_eq!(r["in_mru_list"], true);
    assert_eq!(r["in_servers_key"], true);
    // No single unlabelled time survives the join.
    assert!(r.get("key_last_written").is_none(), "{r}");
}

/// A host in `Servers` only, or in the MRU only, is still exactly one record,
/// and the fields of the key it is not in are null, not borrowed.
#[test]
fn an_rdp_destination_in_one_key_only_is_still_one_record() {
    let cap = rdp_capture(
        Some(&[("MRU0", "fileserver"), ("MRU1", "10.0.0.5")]),
        &[("jumpbox", Some("ops"))],
    );
    let rdp = rdp_records(&cap);
    assert_eq!(rdp.len(), 3, "{rdp:#?}");
    let by = |h: &str| rdp.iter().find(|r| r["host"] == h).unwrap();

    let mru_only = by("10.0.0.5");
    assert_eq!(mru_only["mru_position"], 1);
    assert_eq!(mru_only["in_servers_key"], false);
    assert!(mru_only["servers_key_path"].is_null());
    assert!(mru_only["servers_key_last_written"].is_null());
    assert!(mru_only["servers_key_last_written_scope"].is_null());
    assert!(mru_only["username_hint"].is_null());
    assert_eq!(mru_only["mru_key_last_written_scope"], DEFAULT_SCOPE);

    let servers_only = by("jumpbox");
    assert!(servers_only["mru_position"].is_null());
    assert_eq!(servers_only["mru_positions"], serde_json::json!([]));
    assert_eq!(servers_only["in_mru_list"], false);
    assert!(servers_only["mru_key_path"].is_null());
    assert!(servers_only["mru_key_last_written"].is_null());
    assert!(servers_only["mru_key_last_written_scope"].is_null());
    assert_eq!(servers_only["username_hint"], "ops");
    assert_eq!(
        servers_only["servers_key_last_written_scope"],
        SERVERS_SCOPE
    );

    // Records come out in MRU order, then Servers-only hosts.
    let hosts: Vec<_> = rdp.iter().map(|r| r["host"].as_str().unwrap()).collect();
    assert_eq!(hosts, ["fileserver", "10.0.0.5", "jumpbox"]);
}

/// Host names are compared case-insensitively (Windows host names are), and
/// both spellings stay on the record; a host listed twice in the MRU carries
/// both positions.
#[test]
fn an_rdp_join_ignores_host_case_and_keeps_every_mru_position() {
    let cap = rdp_capture(
        Some(&[("MRU0", "Desktop-A"), ("MRU2", "DESKTOP-A")]),
        &[("desktop-a", Some("alice"))],
    );
    let rdp = rdp_records(&cap);
    assert_eq!(rdp.len(), 1, "{rdp:#?}");
    let r = &rdp[0];
    assert_eq!(r["host"], "Desktop-A", "the MRU spelling, the first seen");
    assert_eq!(r["servers_key_host"], "desktop-a");
    assert_eq!(r["mru_position"], 0);
    assert_eq!(r["mru_positions"], serde_json::json!([0, 2]));
    assert_eq!(r["username_hint"], "alice");
    assert!(r["join_basis"]
        .as_str()
        .unwrap()
        .contains("case-insensitive"));
}

/// `HUNT-245`: the Remote Desktop client's default port is 3389, so `host` and
/// `host:3389` name one destination and are one record, compared
/// case-insensitively; a different port is a different destination. An IP
/// address and a host name are not joined, and the record says so.
#[test]
fn an_rdp_join_treats_the_default_port_as_the_same_destination() {
    let cap = rdp_capture(
        Some(&[
            ("MRU0", "fileserver:3389"),
            ("MRU1", "FILESERVER"),
            ("MRU2", "fileserver:3390"),
            ("MRU3", "[FE80::1]:3389"),
            ("MRU4", "10.0.0.5"),
        ]),
        &[("FileServer", Some("ops")), ("[fe80::1]", None)],
    );
    let rdp = rdp_records(&cap);
    let hosts: Vec<_> = rdp.iter().map(|r| r["host"].as_str().unwrap()).collect();
    assert_eq!(
        hosts,
        [
            "fileserver:3389",
            "fileserver:3390",
            "[FE80::1]:3389",
            "10.0.0.5"
        ],
        "host and host:3389 are one destination; :3390 is another: {rdp:#?}"
    );
    let r = &rdp[0];
    assert_eq!(r["destination"], "fileserver");
    assert_eq!(r["mru_positions"], serde_json::json!([0, 1]));
    assert_eq!(
        r["hosts_as_stored"],
        serde_json::json!(["fileserver:3389", "FILESERVER", "FileServer"])
    );
    assert_eq!(r["servers_key_host"], "FileServer");
    assert_eq!(r["username_hint"], "ops");
    assert_eq!(rdp[1]["destination"], "fileserver:3390");
    assert_eq!(rdp[1]["in_servers_key"], false);
    assert_eq!(rdp[2]["destination"], "[fe80::1]");
    assert_eq!(rdp[2]["servers_key_host"], "[fe80::1]");
    for r in &rdp {
        assert_eq!(r["ip_to_name_join_attempted"], false, "{r}");
        assert!(r["join_basis"].as_str().unwrap().contains("3389"), "{r}");
    }
}

/// `HUNT-248`: one destination with two `Servers` subkeys (`fileserver` and
/// `FileServer:3389`, one destination by `rdp_destination_key`) is ONE record
/// listing both keys, each with its own path, time and scope, and both
/// `UsernameHint` values — the second is not dropped or overwritten.
#[test]
fn an_rdp_destination_with_two_servers_subkeys_is_one_record_listing_both() {
    let cap = rdp_capture(
        Some(&[("MRU0", "fileserver")]),
        &[
            ("fileserver", Some("ops")),
            ("FileServer:3389", Some("admin")),
        ],
    );
    let rdp = rdp_records(&cap);
    assert_eq!(rdp.len(), 1, "one destination, one record: {rdp:#?}");
    let r = &rdp[0];
    assert_eq!(r["servers_key_count"], 2, "{r}");
    let keys = r["servers_keys"].as_array().expect("servers_keys list");
    assert_eq!(keys.len(), 2, "{r}");
    for (k, host) in keys.iter().zip(["fileserver", "FileServer:3389"]) {
        assert_eq!(k["host"], host, "{k}");
        assert!(k["path"]
            .as_str()
            .unwrap()
            .ends_with(&format!(r"\Servers\{host}")));
        assert!(k["last_written"]
            .as_str()
            .unwrap()
            .starts_with("2020-09-19T03:36:25.5804446"));
        assert_eq!(k["last_written_scope"], SERVERS_SCOPE);
    }
    assert_eq!(keys[0]["username_hint"], "ops");
    assert_eq!(keys[1]["username_hint"], "admin");
    assert_eq!(r["username_hints"], serde_json::json!(["ops", "admin"]));
    // The scalars stay the first-seen subkey.
    assert_eq!(r["servers_key_host"], "fileserver");
    assert_eq!(r["username_hint"], "ops");
    assert_eq!(
        r["hosts_as_stored"],
        serde_json::json!(["fileserver", "FileServer:3389"])
    );
    assert!(
        !r["join_basis"].as_str().unwrap().contains("its own record"),
        "{r}"
    );
}

/// `HUNT-248`: the same holds for a destination found only in `Servers`.
#[test]
fn a_servers_only_destination_with_two_subkeys_is_one_record() {
    let cap = rdp_capture(None, &[("jumpbox", None), ("JUMPBOX:3389", Some("ops"))]);
    let rdp = rdp_records(&cap);
    assert_eq!(rdp.len(), 1, "{rdp:#?}");
    let r = &rdp[0];
    assert_eq!(r["in_mru_list"], false);
    assert_eq!(r["servers_key_count"], 2);
    assert_eq!(r["servers_key_host"], "jumpbox");
    // The first non-null hint, from the second subkey; the list names it once.
    assert_eq!(r["username_hint"], "ops");
    assert_eq!(r["username_hints"], serde_json::json!(["ops"]));
    assert!(r["servers_keys"][0]["username_hint"].is_null());
    // The record must say the hint can come from a different subkey than the
    // `servers_key_*` fields, or a reader pairs "ops" with jumpbox's path/time.
    let basis = r["join_basis"].as_str().unwrap();
    assert!(
        basis.contains("username_hint is the first non-null hint")
            && basis.contains("a later subkey"),
        "{basis}"
    );
}

// --- WordWheelQuery (Data Leakage key question 17) --------------------------

/// What the user typed into Windows Explorer's search box is kept in
/// `Explorer\WordWheelQuery`, each value a UTF-16LE string with its NUL. It was
/// shown only as hex in the registry view: key question 17 ("user keywords at
/// the search bar in Windows Explorer") had no decoded answer.
#[test]
fn explorer_search_box_keywords_are_a_recognised_string_mru() {
    let base = r"ROOT\Software\Microsoft\Windows\CurrentVersion\Explorer";
    assert_eq!(
        mru_kind_of(&format!(r"{base}\WordWheelQuery")),
        Some(MruKind::WordWheelQuery)
    );
    assert_eq!(MruKind::WordWheelQuery.as_str(), "word_wheel_query");
    // The bytes the Data Leakage PC's value `0` holds: "secret" and its NUL.
    let body: Vec<u8> = "secret\0"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let e = decode_name_body(MruKind::WordWheelQuery, "0", &body);
    assert_eq!(e.display_name.as_deref(), Some("secret"));
}
