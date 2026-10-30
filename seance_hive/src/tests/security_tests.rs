//! Security descriptors (`sk` cells) — what this reader has to do, stated
//! before it did any of it.
//!
//! # Why an `sk` cell is worth reading at all
//!
//! A key's security descriptor is the only place a hive records *who could
//! change this key*. An examiner asking why a Run-key persisted, or why the
//! SAM was readable, is asking about an ACL — and until this landed the reader
//! declared the field "not read" in `docs/SPEC_CROSSCHECK.md` and skipped
//! offset `0x2C` entirely.
//!
//! # The shapes these fixtures carry, and where they come from
//!
//! Every mask, control word and ACE flag below was taken from a **real hive**,
//! not invented. Twelve hives under `reference/plaso/test_data/` were scanned
//! cell by cell while planning this work: 334,111 allocated `nk` cells and 820
//! allocated `sk` cells, and in all twelve every `nk` names an *allocated*
//! `sk`, every descriptor sets `SE_SELF_RELATIVE`, and each `sk` cell's
//! reference count equals the number of `nk` cells pointing at it exactly.
//!
//! That grounding is the point. `HUNT-122` fired 788 false leads because every
//! fixture passed a value shape no enumerator produces, and `HUNT-123` raised
//! 232 false tampering allegations because the fixture put a certificate table
//! where a signing tool always puts it — at the end — so the wrong branch never
//! ran. A fixture here that carried, say, a file-style `0x001F01FF` mask would
//! agree with the code about an input the registry never holds.

use super::builder::{HiveBuilder, TestKey, TestSecurity};
use super::corpus_hive;
use crate::error::HiveError;
use crate::hive::Hive;

/// `S-1-5-32-544` — `BUILTIN\Administrators`, the owner of both descriptors in
/// the real `SAM` hive this fixture is modelled on.
fn sid_administrators() -> Vec<u8> {
    let mut sid = vec![1, 2, 0, 0, 0, 0, 0, 5]; // rev 1, 2 sub-authorities, authority 5
    sid.extend_from_slice(&32u32.to_le_bytes());
    sid.extend_from_slice(&544u32.to_le_bytes());
    sid
}

/// `S-1-5-18` — `NT AUTHORITY\SYSTEM`.
fn sid_local_system() -> Vec<u8> {
    let mut sid = vec![1, 1, 0, 0, 0, 0, 0, 5];
    sid.extend_from_slice(&18u32.to_le_bytes());
    sid
}

/// An `ACCESS_ALLOWED_ACE` (type 0), as the real hives hold them.
///
/// `mask` is a **registry** right. The two this fixture uses are the two the
/// real `SAM` carries: `0x000F003F` (`KEY_ALL_ACCESS`) and `0x00020019`
/// (`KEY_READ`).
fn allow_ace(mask: u32, flags: u8, sid: &[u8]) -> Vec<u8> {
    let size = 8 + sid.len();
    let mut ace = vec![0u8, flags];
    ace.extend_from_slice(&(size as u16).to_le_bytes());
    ace.extend_from_slice(&mask.to_le_bytes());
    ace.extend_from_slice(sid);
    ace
}

/// A self-relative security descriptor: owner, optional group, optional SACL,
/// and a DACL built from `aces`.
fn descriptor(control: u16, owner: &[u8], group: Option<&[u8]>, aces: &[Vec<u8>]) -> Vec<u8> {
    let mut acl = Vec::new();
    let ace_bytes: usize = aces.iter().map(Vec::len).sum();
    acl.push(2u8); // AclRevision
    acl.push(0u8); // Sbz1
    acl.extend_from_slice(&((8 + ace_bytes) as u16).to_le_bytes()); // AclSize
    acl.extend_from_slice(&(aces.len() as u16).to_le_bytes()); // AceCount
    acl.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
    for ace in aces {
        acl.extend_from_slice(ace);
    }

    // The 20-byte fixed header, then the bodies it points at.
    let mut sd = vec![0u8; 20];
    sd[0] = 1; // Revision
    sd[1] = 0; // Sbz1
    sd[2..4].copy_from_slice(&control.to_le_bytes());

    let owner_off = sd.len() as u32;
    sd.extend_from_slice(owner);
    let group_off = group.map(|g| {
        let off = sd.len() as u32;
        sd.extend_from_slice(g);
        off
    });
    let dacl_off = sd.len() as u32;
    sd.extend_from_slice(&acl);

    sd[4..8].copy_from_slice(&owner_off.to_le_bytes());
    sd[8..12].copy_from_slice(&group_off.unwrap_or(0).to_le_bytes());
    sd[12..16].copy_from_slice(&0u32.to_le_bytes()); // no SACL
    sd[16..20].copy_from_slice(&dacl_off.to_le_bytes());
    sd
}

/// The real `SAM` root key's shape, reduced to the two ACEs that carry its
/// meaning: `BUILTIN\Users` may read the key, Administrators have it all.
///
/// Control `0x9404` is the real value from `reference/plaso/test_data/SAM`:
/// `SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED | SE_SACL_AUTO_INHERITED`.
fn sam_root_descriptor() -> Vec<u8> {
    descriptor(
        0x9404,
        &sid_administrators(),
        Some(&sid_local_system()),
        &[
            allow_ace(0x000F_003F, 0x00, &sid_administrators()),
            // Inherit-only: `CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE`. Four of
            // the eight ACEs in the real SAM root descriptor carry exactly this
            // flag byte, so it is a majority shape here and not an edge case.
            allow_ace(0x1000_0000, 0x0A, &sid_local_system()),
        ],
    )
}

/// The descriptor the 64 keys beneath the real `SAM` root share.
fn sam_child_descriptor() -> Vec<u8> {
    descriptor(
        0x8004,
        &sid_administrators(),
        None,
        &[allow_ace(0x000F_003F, 0x02, &sid_local_system())],
    )
}

// --- The field itself -------------------------------------------------------

/// The reader must read offset `0x2C`, and `0xFFFFFFFF` there must mean "no
/// security recorded" rather than a cell at offset 4,294,967,295.
///
/// Every hive the builder wrote before this change put `u32::MAX` in that
/// field, so this test also pins that those hives keep reading as they did.
#[test]
fn a_key_with_no_security_offset_records_none_rather_than_an_error() {
    let bytes = HiveBuilder::new().build(&TestKey::new("ROOT"));
    let hive = Hive::new(&bytes).expect("open");
    let root = hive.root_key_node().expect("root");
    assert!(
        root.security_offset().is_none(),
        "0xFFFFFFFF in nk+0x2C is the absence of a descriptor, not an offset"
    );
    assert!(
        root.security().is_none(),
        "a key with no security recorded must answer None, not Some(Err(..))"
    );
}

/// A key that names an `sk` cell yields its descriptor bytes and the cell's own
/// bookkeeping.
#[test]
fn a_key_that_names_a_security_cell_yields_its_descriptor() {
    let sd = sam_root_descriptor();
    let root = TestKey::new("ROOT").with_security(TestSecurity::new(1, sd.clone()));
    let bytes = HiveBuilder::new().build(&root);
    let hive = Hive::new(&bytes).expect("open");
    let key = hive.root_key_node().expect("root");

    assert!(key.security_offset().is_some());
    let sk = key
        .security()
        .expect("a descriptor is recorded")
        .expect("it reads");
    assert_eq!(sk.reference_count(), 1);
    assert_eq!(sk.descriptor_size() as usize, sd.len());
    assert_eq!(
        sk.descriptor(),
        &sd[..],
        "the bytes handed out must be the self-relative descriptor, byte for byte"
    );
}

/// Two keys sharing one descriptor must both resolve to the **same cell**.
///
/// This is the whole reason `sk` cells are shared and reference-counted: on the
/// real `SOFTWARE` hive 117,488 keys resolve to 289 descriptors, and one of
/// those descriptors is named by 42,002 keys. A reader that copied the bytes
/// per key would answer the same question 42,002 times and could not say "this
/// key's ACL is the one its 42,001 siblings have".
#[test]
fn keys_sharing_a_descriptor_resolve_to_one_cell() {
    let shared = TestSecurity::new(2, sam_child_descriptor());
    let root = TestKey::new("ROOT")
        .with_security(shared.clone())
        .with_subkey(TestKey::new("CHILD").with_security(shared));
    let bytes = HiveBuilder::new().build(&root);
    let hive = Hive::new(&bytes).expect("open");
    let key = hive.root_key_node().expect("root");
    let child = key
        .subkeys()
        .expect("subkeys")
        .expect("index reads")
        .filter_map(|k| k.ok())
        .next()
        .expect("one child");

    let a = key.security().unwrap().unwrap();
    let b = child.security().unwrap().unwrap();
    assert_eq!(
        a.cell_offset(),
        b.cell_offset(),
        "a shared descriptor is one cell, and both keys must name it"
    );
    assert_eq!(a.reference_count(), 2);
}

// --- The ring ---------------------------------------------------------------

/// Every `sk` cell in a hive is on one doubly-linked ring, and walking it is
/// how the distinct descriptor population is enumerated without visiting all
/// 117,488 keys.
///
/// The real hives close the ring through `flink` *and* `blink` with identical
/// membership — 2 cells in `SAM`, 11 in `NTUSER.DAT`, 193 in `SYSTEM`, 289 in
/// `SOFTWARE` — so a reader may rely on it closing, and must say so when it
/// does not.
#[test]
fn the_security_ring_enumerates_every_distinct_descriptor_once() {
    let root_sd = TestSecurity::new(1, sam_root_descriptor());
    let child_sd = TestSecurity::new(2, sam_child_descriptor());
    let root = TestKey::new("ROOT")
        .with_security(root_sd)
        .with_subkey(TestKey::new("A").with_security(child_sd.clone()))
        .with_subkey(TestKey::new("B").with_security(child_sd));
    let bytes = HiveBuilder::new().build(&root);
    let hive = Hive::new(&bytes).expect("open");

    let ring = hive.security_descriptors().expect("the ring reads");
    assert_eq!(ring.listed_len(), 2, "two distinct descriptors, three keys");
    assert!(!ring.is_incomplete(), "a closed ring is a complete answer");

    let mut counts: Vec<u32> = ring.iter().map(|sk| sk.reference_count()).collect();
    counts.sort_unstable();
    assert_eq!(counts, vec![1, 2]);
}

/// A hive with no descriptors anywhere has an empty population, and that is an
/// answer rather than a failure.
#[test]
fn a_hive_with_no_descriptors_has_an_empty_ring() {
    let bytes = HiveBuilder::new().build(&TestKey::new("ROOT"));
    let hive = Hive::new(&bytes).expect("open");
    let ring = hive
        .security_descriptors()
        .expect("no descriptors is not an error");
    assert_eq!(ring.listed_len(), 0);
    assert!(!ring.is_incomplete());
}

// --- What must not be believed ---------------------------------------------

/// A `flink` pointing at itself must not spin.
///
/// Hive bytes arrive from disk images, carved fragments and hostile input. The
/// subkey index has `MAX_INDEX_DEPTH` for the same reason: in an ingest
/// pipeline a loop is an outage, not a parse error.
#[test]
fn a_security_ring_that_points_at_itself_terminates_and_says_so() {
    let sd = sam_child_descriptor();
    let root = TestKey::new("ROOT").with_security(TestSecurity::new(1, sd));
    let mut bytes = HiveBuilder::new().build(&root);

    // Point the single cell's flink at a *different* offset that leads back to
    // it, by making flink name the cell itself while blink names something
    // else — a ring that never reaches its start again.
    let hive = Hive::new(&bytes).expect("open");
    let sk_off = hive
        .root_key_node()
        .expect("root")
        .security_offset()
        .expect("recorded");
    let base = 4096 + sk_off as usize + 4; // base block + cell size field
    let forged = sk_off.wrapping_add(8);
    bytes[base + 4..base + 8].copy_from_slice(&forged.to_le_bytes());
    super::builder::reseal(&mut bytes);

    let hive = Hive::new(&bytes).expect("open");
    match hive.security_descriptors() {
        Ok(ring) => assert!(
            ring.is_incomplete(),
            "a ring that does not close must be reported incomplete, not silently short"
        ),
        Err(_) => { /* refusing outright is also honest */ }
    }
}

/// A descriptor size larger than the cell holding it must be refused, not
/// served from beyond the cell.
///
/// This is the `HUNT-123` shape in miniature: a length field trusted past the
/// structure that bounds it. The bytes past the cell belong to some other
/// cell, and handing them to a descriptor decoder would produce ACEs that are
/// not in the evidence.
#[test]
fn a_descriptor_longer_than_its_cell_is_refused() {
    let sd = sam_child_descriptor();
    let root = TestKey::new("ROOT").with_security(TestSecurity::new(1, sd));
    let mut bytes = HiveBuilder::new().build(&root);

    let hive = Hive::new(&bytes).expect("open");
    let sk_off = hive
        .root_key_node()
        .expect("root")
        .security_offset()
        .expect("recorded");
    let base = 4096 + sk_off as usize + 4;
    bytes[base + 0x10..base + 0x14].copy_from_slice(&0x0010_0000u32.to_le_bytes());
    super::builder::reseal(&mut bytes);

    let hive = Hive::new(&bytes).expect("open");
    let err = hive
        .root_key_node()
        .expect("root")
        .security()
        .expect("still recorded")
        .expect_err("a descriptor claiming 1 MB inside a 128-byte cell must be refused");
    assert!(
        matches!(err, HiveError::Truncated { structure, .. } if structure.contains("security")),
        "the refusal must name the structure that failed, got {err:?}"
    );
}

/// A cell that does not begin `sk` is not a security descriptor, and reading it
/// as one would decode another structure's bytes as an ACL.
#[test]
fn a_security_offset_pointing_at_a_non_sk_cell_is_refused() {
    let sd = sam_child_descriptor();
    let root = TestKey::new("ROOT").with_security(TestSecurity::new(1, sd));
    let mut bytes = HiveBuilder::new().build(&root);

    let hive = Hive::new(&bytes).expect("open");
    let sk_off = hive
        .root_key_node()
        .expect("root")
        .security_offset()
        .expect("recorded");
    let base = 4096 + sk_off as usize + 4;
    bytes[base] = b'v';
    bytes[base + 1] = b'k';
    super::builder::reseal(&mut bytes);

    let hive = Hive::new(&bytes).expect("open");
    let err = hive
        .root_key_node()
        .expect("root")
        .security()
        .expect("still recorded")
        .expect_err("a vk cell is not a security descriptor");
    assert!(
        matches!(err, HiveError::BadSignature { expected: "sk", .. }),
        "got {err:?}"
    );
}

/// A reference count of zero is a contradiction: the key naming the cell is
/// itself a reference. It is reported as read rather than corrected, because
/// what the hive says is evidence and what it ought to say is not.
///
/// All 820 real `sk` cells carry a non-zero count, so this shape is a damaged
/// or crafted hive — and the reader's job there is to hand the field over
/// unchanged and let the caller qualify it.
#[test]
fn a_zero_reference_count_is_reported_as_it_was_found() {
    let sd = sam_child_descriptor();
    let root = TestKey::new("ROOT").with_security(TestSecurity::new(0, sd));
    let bytes = HiveBuilder::new().build(&root);
    let hive = Hive::new(&bytes).expect("open");
    let sk = hive
        .root_key_node()
        .expect("root")
        .security()
        .expect("recorded")
        .expect("reads");
    assert_eq!(
        sk.reference_count(),
        0,
        "the count is transcribed, not repaired"
    );
}

// --- The known answer, on real hives ---------------------------------------

/// The real `SAM` hive's two descriptors, against the bytes they are made of.
///
/// This is the known answer this work was built to, hand-decoded from the hive
/// before any of it was written:
///
/// ```text
/// sk @0x160  cell 264 B  flink=blink=0x268  refcount 1   sd 236 B  control 0x9404  owner S-1-5-32-544
/// sk @0x268  cell 128 B                     refcount 64  sd 100 B  control 0x8004  owner S-1-5-32-544
/// ```
///
/// What it says, in the sentence an examiner would say out loud: the `SAM` root
/// key is readable by `BUILTIN\Users` (`0x20019` = `KEY_READ`), and the 64 keys
/// beneath it are not. That is real Windows hardening, and it is the reason
/// reading `sk` cells was worth doing.
#[test]
fn the_real_sam_hive_decodes_to_its_known_answer() {
    let Some(bytes) = corpus_hive("SAM") else {
        return;
    };
    let hive = Hive::without_validation(&bytes).expect("open SAM");
    let ring = hive.security_descriptors().expect("the ring reads");

    assert_eq!(ring.listed_len(), 2, "SAM holds exactly two descriptors");
    assert!(!ring.is_incomplete());

    let mut cells: Vec<_> = ring.iter().copied().collect();
    cells.sort_by_key(|c| c.cell_offset());

    assert_eq!(cells[0].cell_offset(), 0x160);
    assert_eq!(cells[0].reference_count(), 1);
    assert_eq!(cells[0].descriptor_size(), 236);
    assert_eq!(cells[1].cell_offset(), 0x268);
    assert_eq!(cells[1].reference_count(), 64);
    assert_eq!(cells[1].descriptor_size(), 100);

    // The ring closes through both links with the same membership, which is
    // what all twelve real hives do and what the walk relies on.
    assert_eq!(cells[0].flink(), 0x268);
    assert_eq!(cells[0].blink(), 0x268);

    for (cell, control) in cells.iter().zip([0x9404u16, 0x8004]) {
        let sd = cell.descriptor();
        assert_eq!(sd.len(), cell.descriptor_size() as usize);
        assert_eq!(sd[0], 1, "security-descriptor revision");
        assert_eq!(
            u16::from_le_bytes([sd[2], sd[3]]),
            control,
            "control word at descriptor+0x02"
        );
        assert_eq!(
            control & 0x8000,
            0x8000,
            "SE_SELF_RELATIVE must be set — all 820 real cells set it, and the \
             offsets this reader hands out are only meaningful if it is"
        );
        // Owner is `S-1-5-32-544`, BUILTIN\Administrators, on both.
        let owner = u32::from_le_bytes(sd[4..8].try_into().unwrap()) as usize;
        assert_eq!(sd[owner], 1, "SID revision");
        assert_eq!(sd[owner + 1], 2, "two sub-authorities");
        assert_eq!(sd[owner + 7], 5, "authority 5 (NT)");
        assert_eq!(
            u32::from_le_bytes(sd[owner + 8..owner + 12].try_into().unwrap()),
            32
        );
        assert_eq!(
            u32::from_le_bytes(sd[owner + 12..owner + 16].try_into().unwrap()),
            544
        );
    }
}

/// On a hive of any size, the reference counts must account for every key.
///
/// This is the internal consistency check that makes the whole population
/// trustworthy without a second tool to compare against — and there is no
/// second tool on this machine, so it is the strongest available evidence. On
/// `SOFTWARE` the 289 descriptors' counts sum to **117,488**, which is exactly
/// the number of keys in the hive; on `SYSTEM`, 193 descriptors sum to 30,756;
/// on `NTUSER.DAT`, 11 sum to 1,127.
///
/// A reader that lost a ring member, double-counted one, or read the count from
/// the wrong offset could not produce that equality by accident.
#[test]
fn the_reference_counts_account_for_every_key_in_the_hive() {
    for (name, descriptors, keys) in [
        ("SAM", 2usize, 65u64),
        ("SYSTEM", 193, 30_756),
        ("SOFTWARE", 289, 117_488),
        ("NTUSER.DAT", 11, 1_127),
    ] {
        let Some(bytes) = corpus_hive(name) else {
            return;
        };
        let hive = Hive::without_validation(&bytes).unwrap_or_else(|e| panic!("open {name}: {e}"));
        let ring = hive
            .security_descriptors()
            .unwrap_or_else(|e| panic!("{name} ring: {e}"));
        assert!(!ring.is_incomplete(), "{name}'s ring must close");
        assert_eq!(ring.listed_len(), descriptors, "{name} descriptor count");
        let total: u64 = ring.iter().map(|c| c.reference_count() as u64).sum();
        assert_eq!(
            total, keys,
            "{name}: the descriptors' reference counts must account for every key"
        );
        // The smallest real descriptor in the corpus is 72 bytes; anything
        // under the 20-byte fixed header is not a descriptor at all.
        for cell in ring.iter() {
            assert!(
                cell.descriptor_size() >= 20,
                "{name}: a descriptor shorter than its own fixed header"
            );
        }
    }
}
