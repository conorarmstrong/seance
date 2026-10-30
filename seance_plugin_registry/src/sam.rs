//! Local accounts: the `F` and `V` values under `SAM\Domains\Account\Users`.
//!
//! `ROADMAP` §2.6. `SAM` stores one key per account, named for the account's
//! RID in hex, holding two `REG_BINARY` values. `F` is a fixed 80-byte record
//! carrying the RID, the account-control word and the account's times; `V` is
//! a self-describing structure — an array of offset/length descriptors
//! followed by their payloads — carrying the strings and the password-hash
//! blobs.
//!
//! Until this shipped, only the account **names** were read, from the key
//! components under `Users\Names`. The RIDs and the last-login times were in
//! these two values and nothing parsed them.
//!
//! # Only what the evidence proves
//!
//! Five `F` offsets are decoded, and each was established from the reference
//! hive itself rather than from a recollection of the layout — see
//! `sam_tests.rs` for the proof of each. The rest of `F` is **named on the
//! record as not read**: the account-expiry slot is zero on two accounts and
//! the `0x7FFF…` never-sentinel on the third, so a sentinel proves the slot is
//! optional and not what it means; the bad-password time is zero on all three;
//! the failed-count `u16` is zero on all three, so its offset cannot be told
//! apart from any other always-zero field; and the country/codepage pair is
//! non-zero on one account only.
//!
//! An absence named is the difference between "this build does not read that"
//! and "this machine has no such record", and this file is written so that a
//! reader can tell which they are looking at.
//!
//! # The two failures it is written against
//!
//! **A zero time is not 1601.** Guest never logged on and never had a password
//! set. A converter that runs unconditionally prints "Guest, last logon
//! 1601-01-01" — a fabricated logon event on an account that has never been
//! used — and on the reference hive alone it would do so eleven times across
//! three accounts.
//!
//! **A zero-length descriptor still carries a live offset.** On the reference
//! hive, `Administrator`'s full-name and comment descriptors share one offset,
//! and the full name's length is zero. A reader that resolves the offset and
//! scans to a NUL prints "Built-in account for administering the
//! computer/domain" as the account's full name. On `Preston` the same bug
//! prints the all-`0xFF` logon-hours bitmap. The declared length bounds every
//! read here, and a zero length is an absence whatever its offset points at.

use serde_json::{json, Map, Value};

/// The fixed length of an `F` value. Checked before any offset is used: a
/// short `F` read at these offsets returns whatever follows it in the cell.
pub const F_VALUE_BYTES: usize = 0x50;

/// Proven: the account's RID, and it equals the hex key name on all three
/// accounts of the reference hive.
const F_RID: usize = 0x30;
/// Proven: the primary group's RID. Constant (513) across the reference hive,
/// so the offset rests on an in-hive cross-reference to the key
/// `Groups\00000201` rather than on variation.
const F_PRIMARY_GROUP_RID: usize = 0x34;
/// Proven: the account-control (`ACB_*`) word.
const F_ACCOUNT_CONTROL: usize = 0x38;
/// Proven: last logon.
const F_LAST_LOGON: usize = 0x08;
/// Proven: last password set.
const F_LAST_PASSWORD_SET: usize = 0x18;
/// Proven: a `u16` logon count. Read as a `u32` at `0x40` it is 393,216.
const F_LOGIN_COUNT: usize = 0x42;

/// The `F` fields this build does not read, and why not, said on every record.
///
/// This list exists so that "no expiry date on this account" is never confused
/// with "this build does not read the expiry slot".
const F_FIELDS_NOT_READ: &[&str] = &[
    "account expiry (F+0x20): zero on two accounts of the reference hive and the 0x7FFFFFFFFFFFFFFF \
     never-sentinel on the third. A sentinel establishes that the slot is an optional FILETIME; it \
     does not establish that the slot is the expiry. Not read.",
    "last incorrect password (F+0x28): zero on all three accounts of the reference hive, so the \
     eight bytes are genuinely unset there and nothing available to this build confirms the \
     offset. Not read.",
    "failed login count (F+0x40, u16): zero on all three accounts. Because it never varies, this \
     offset cannot be told apart from any other field that is zero on every account here -- the \
     logon count at F+0x42 was established precisely because it does vary. Not read.",
    "F+0x10 (eight bytes): zero on all three accounts. FILETIME-shaped by position only; decoded \
     it would yield 1601-01-01. Not read.",
    "country code and codepage (F+0x3c, F+0x3e): non-zero on one account of the reference hive \
     only. One self-identifying constant is not two agreeing accounts. Not read.",
    "F+0x44, F+0x48 and F+0x4c: per-account and unexplained. Not read.",
];

/// The account-control bits the reference hive exercises, and no others.
///
/// A bit no evidence has exercised is reported as the bit it is and is not
/// named: the same discipline `seance_core::secdesc` uses for an access-mask
/// bit the object kind does not define.
const ACCOUNT_CONTROL_NAMES: &[(u32, &str)] = &[
    (0x0001, "disabled"),
    (0x0004, "password_not_required"),
    (0x0010, "normal_account"),
    (0x0200, "password_never_expires"),
];

/// `ACB_AUTOLOCK`. Named here only so the record can say that no account in
/// the reference hive sets it and this build therefore asserts nothing about
/// lock-out either way.
const ACB_AUTOLOCK: u32 = 0x0400;

/// Recognise an account key, returning its hex RID.
///
/// `…\SAM\Domains\Account\Users\<8 hex digits>`, and nothing else: `Users`
/// itself, `Users\Names`, a key under `Builtin`, and the `Groups` and
/// `Aliases` siblings all hold different things.
pub fn sam_account_key(key_path: &str) -> Option<String> {
    let segments: Vec<&str> = key_path.split('\\').filter(|s| !s.is_empty()).collect();
    let (name, parents) = segments.split_last()?;
    if !(name.len() == 8 && name.bytes().all(|b| b.is_ascii_hexdigit())) {
        return None;
    }
    account_users_parent(parents).then(|| name.to_string())
}

/// Recognise a name-index key, returning the account name.
///
/// `…\SAM\Domains\Account\Users\Names\<name>` — the name is the key's own
/// component, and a name may contain a space (`Mr. Evil`, on the CFReDS
/// Hacking Case).
pub fn sam_name_key(key_path: &str) -> Option<String> {
    let segments: Vec<&str> = key_path.split('\\').filter(|s| !s.is_empty()).collect();
    let (name, parents) = segments.split_last()?;
    let (names, rest) = parents.split_last()?;
    if !names.eq_ignore_ascii_case("Names") {
        return None;
    }
    account_users_parent(rest).then(|| name.to_string())
}

/// Whether the trailing segments are `…\Domains\Account\Users`.
fn account_users_parent(parents: &[&str]) -> bool {
    let mut it = parents.iter().rev();
    let users = it.next();
    let account = it.next();
    let domains = it.next();
    users.is_some_and(|s| s.eq_ignore_ascii_case("Users"))
        && account.is_some_and(|s| s.eq_ignore_ascii_case("Account"))
        && domains.is_some_and(|s| s.eq_ignore_ascii_case("Domains"))
}

/// The RID an account key's name states.
pub fn rid_from_key_name(key_name: &str) -> Option<u32> {
    (key_name.len() == 8)
        .then(|| u32::from_str_radix(key_name, 16).ok())
        .flatten()
}

fn le_u16(d: &[u8], at: usize) -> Option<u16> {
    d.get(at..at + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
}

fn le_u32(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

fn le_u64(d: &[u8], at: usize) -> Option<u64> {
    d.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
}

/// The five fields the `F` value's evidence establishes.
#[derive(Clone, Debug)]
pub struct FValue {
    pub rid: u32,
    pub primary_group_rid: u32,
    pub account_control: u32,
    /// The raw FILETIME, kept so a test pins the offset and not its rendering.
    /// `Some(0)` is a recorded zero — the account never logged on — which is a
    /// different thing from the field being unreadable.
    pub last_logon_filetime: Option<u64>,
    pub last_password_set_filetime: Option<u64>,
    pub login_count: u16,
}

impl FValue {
    /// Parse an `F` value, or `None` when it is not the fixed 80 bytes.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != F_VALUE_BYTES {
            return None;
        }
        Some(Self {
            rid: le_u32(bytes, F_RID)?,
            primary_group_rid: le_u32(bytes, F_PRIMARY_GROUP_RID)?,
            account_control: le_u32(bytes, F_ACCOUNT_CONTROL)?,
            last_logon_filetime: le_u64(bytes, F_LAST_LOGON),
            last_password_set_filetime: le_u64(bytes, F_LAST_PASSWORD_SET),
            login_count: le_u16(bytes, F_LOGIN_COUNT)?,
        })
    }

    /// The bits this build names, in bit order.
    pub fn named_flags(&self) -> Vec<&'static str> {
        ACCOUNT_CONTROL_NAMES
            .iter()
            .filter(|(bit, _)| self.account_control & bit != 0)
            .map(|(_, name)| *name)
            .collect()
    }

    /// The set bits this build does not name, as a mask.
    pub fn unnamed_bits(&self) -> u32 {
        let named: u32 = ACCOUNT_CONTROL_NAMES.iter().map(|(b, _)| b).sum();
        self.account_control & !named
    }
}

/// Descriptors in a `V` value's array, measured on all three reference
/// accounts.
pub const V_DESCRIPTOR_COUNT: usize = 17;
/// Bytes per descriptor: offset, length, and a third word this build does not
/// interpret.
pub const V_DESCRIPTOR_BYTES: usize = 12;
/// Descriptor offsets are relative to this point in the value, which is the
/// end of the array.
pub const V_PAYLOAD_BASE: usize = V_DESCRIPTOR_COUNT * V_DESCRIPTOR_BYTES;

/// The security descriptor.
pub const V_SLOT_SECURITY: usize = 0;
/// The account name. Agrees with the `Names` key on all three reference
/// accounts, which is what makes it two independent routes rather than one.
pub const V_SLOT_USERNAME: usize = 1;
/// The full name.
pub const V_SLOT_FULL_NAME: usize = 2;
/// The account comment.
pub const V_SLOT_COMMENT: usize = 3;
/// The LM password-hash blob.
pub const V_SLOT_LM_HASH: usize = 13;
/// The NT password-hash blob.
pub const V_SLOT_NT_HASH: usize = 14;

/// A blob of this length or less is a header with no hash material after it.
/// Guest's slot 14 is exactly four bytes, which is why the account with no
/// password is distinguishable from one whose hash this build cannot decrypt.
const HASH_BLOB_HEADER_BYTES: u32 = 4;

/// One descriptor, as stored.
#[derive(Clone, Copy, Debug)]
pub struct VDescriptor {
    pub offset: u32,
    pub length: u32,
    /// The third word. Not interpreted; carried so the census is complete.
    pub third_word: u32,
}

/// What the `V` value yielded.
#[derive(Clone, Debug)]
pub struct VValue {
    pub descriptors: Vec<VDescriptor>,
    pub username: Option<String>,
    pub full_name: Option<String>,
    pub comment: Option<String>,
    /// Whether slot 14 holds hash material beyond its header. `None` when the
    /// slot is absent altogether.
    pub nt_hash_material_present: Option<bool>,
    pub lm_hash_material_present: Option<bool>,
    /// Whether slot 0 held a security descriptor, and how many bytes.
    pub security_descriptor_bytes: Option<u32>,
    /// Descriptors this build refused to resolve, each said in words.
    pub out_of_bounds: Vec<String>,
}

impl VValue {
    /// Parse a `V` value, or `None` when it cannot hold its own array.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < V_PAYLOAD_BASE {
            return None;
        }
        let descriptors: Vec<VDescriptor> = (0..V_DESCRIPTOR_COUNT)
            .map(|i| {
                let at = i * V_DESCRIPTOR_BYTES;
                VDescriptor {
                    offset: le_u32(bytes, at).unwrap_or(0),
                    length: le_u32(bytes, at + 4).unwrap_or(0),
                    third_word: le_u32(bytes, at + 8).unwrap_or(0),
                }
            })
            .collect();

        let mut out_of_bounds = Vec::new();
        let username = string_at(
            bytes,
            &descriptors,
            V_SLOT_USERNAME,
            "the account name",
            &mut out_of_bounds,
        );
        let full_name = string_at(
            bytes,
            &descriptors,
            V_SLOT_FULL_NAME,
            "the full name",
            &mut out_of_bounds,
        );
        let comment = string_at(
            bytes,
            &descriptors,
            V_SLOT_COMMENT,
            "the comment",
            &mut out_of_bounds,
        );

        // Hash material: the DECLARED LENGTH, never the bytes. A blob of the
        // header alone is an account with no stored hash, which is a different
        // answer from a hash this build does not decrypt.
        let material = |slot: usize| -> Option<bool> {
            let d = descriptors.get(slot)?;
            (d.length > 0).then_some(d.length > HASH_BLOB_HEADER_BYTES)
        };

        Some(Self {
            nt_hash_material_present: material(V_SLOT_NT_HASH),
            lm_hash_material_present: material(V_SLOT_LM_HASH),
            security_descriptor_bytes: descriptors
                .get(V_SLOT_SECURITY)
                .map(|d| d.length)
                .filter(|n| *n > 0),
            username,
            full_name,
            comment,
            descriptors,
            out_of_bounds,
        })
    }
}

/// One local account.
#[derive(Clone, Debug)]
pub struct LocalAccount {
    pub key_name: String,
    pub rid_from_key: Option<u32>,
    pub f: Option<FValue>,
    /// The length of an `F` that was there and was not the fixed 80 bytes.
    pub f_len_seen: usize,
    pub v: Option<VValue>,
    /// The name from the `Users\Names` index, when the walk reached it.
    pub name_from_index: Option<String>,
    pub key_path: Option<String>,
    pub key_last_written: Option<String>,
}

impl LocalAccount {
    pub fn new(
        key_name: &str,
        f: Option<FValue>,
        name_from_index: Option<&str>,
        f_len_seen: usize,
    ) -> Self {
        Self {
            key_name: key_name.to_string(),
            rid_from_key: rid_from_key_name(key_name),
            f,
            f_len_seen,
            v: None,
            name_from_index: name_from_index.map(str::to_string),
            key_path: None,
            key_last_written: None,
        }
    }

    pub fn with_v(mut self, v: VValue) -> Self {
        self.v = Some(v);
        self
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("type".into(), json!("LocalAccount"));

        let v_name = self.v.as_ref().and_then(|v| v.username.clone());
        let name = v_name
            .clone()
            .or_else(|| self.name_from_index.clone())
            .unwrap_or_else(|| format!("RID {}", self.key_name));
        m.insert("name".into(), json!(name));
        m.insert(
            "username".into(),
            json!(v_name.or(self.name_from_index.clone())),
        );
        m.insert("key_name".into(), json!(self.key_name));

        // The RID: the key name is the anchor, and `F` is the cross-check.
        m.insert("rid".into(), json!(self.rid_from_key));
        if let Some(f) = &self.f {
            m.insert("rid_in_f_value".into(), json!(f.rid));
            if self.rid_from_key.is_some_and(|k| k != f.rid) {
                m.insert(
                    "rid_conflict".into(),
                    json!(format!(
                        "This account's key is named {} -- RID {} -- and the RID stored in its F \
                         value is {}. Both are reported; this build takes the key name as the \
                         account's RID, because that is the name the rest of the registry and the \
                         profile list join on, and states the disagreement rather than choosing \
                         silently.",
                        self.key_name,
                        self.rid_from_key.unwrap_or_default(),
                        f.rid
                    )),
                );
            }
            m.insert("primary_group_rid".into(), json!(f.primary_group_rid));
            m.insert("login_count".into(), json!(f.login_count));

            // The times. A zero is not recorded and must not become 1601.
            let (logon, logon_why) = time_or_reason(f.last_logon_filetime, "logged on");
            m.insert("last_logon".into(), logon);
            if let Some(why) = logon_why {
                m.insert("last_logon_absent_reason".into(), json!(why));
            }
            let (pw, pw_why) = time_or_reason(f.last_password_set_filetime, "had a password set");
            m.insert("last_password_set".into(), pw);
            if let Some(why) = pw_why {
                m.insert("last_password_set_absent_reason".into(), json!(why));
            }

            // The account-control word.
            m.insert("account_control_raw".into(), json!(f.account_control));
            m.insert("account_control_flags".into(), json!(f.named_flags()));
            m.insert(
                "account_enabled".into(),
                json!(f.account_control & 0x0001 == 0),
            );
            m.insert(
                "password_not_required".into(),
                json!(f.account_control & 0x0004 != 0),
            );
            // Lock-out is the bit no account in the reference hive sets, so
            // this build asserts nothing about it either way.
            m.insert("account_locked_out".into(), Value::Null);
            m.insert(
                "account_locked_out_reason".into(),
                json!(format!(
                    "The lock-out bit is 0x{ACB_AUTOLOCK:04X} of the account-control word. This \
                     account's word is 0x{:04X}, and no account in the reference hive this \
                     decoder was established against sets that bit -- so the bit's position is \
                     not exercised by any evidence available to this build and it is not \
                     asserted either way. It is included in the raw word and in any unnamed bits.",
                    f.account_control
                )),
            );
            let unnamed = f.unnamed_bits();
            if unnamed != 0 {
                m.insert(
                    "account_control_unnamed_bits".into(),
                    json!(format!(
                        "0x{unnamed:04X} of this account's control word is set and is not one of \
                         the bits this build names. It is reported as the bits it is rather than \
                         folded into a flag, because an examiner is entitled to the difference \
                         between a flag and whatever this is."
                    )),
                );
            }
            m.insert("f_fields_not_read".into(), json!(F_FIELDS_NOT_READ));
        } else {
            m.insert(
                "f_value_note".into(),
                json!(format!(
                    "This account's F value is {} byte(s), not the {F_VALUE_BYTES} this format \
                     fixes it at, so none of its fixed offsets were read. Reading them anyway \
                     would publish whatever follows the value as this account's RID and times. \
                     The RID above is the key's own name.",
                    self.f_len_seen
                )),
            );
        }

        if let Some(v) = &self.v {
            m.insert("full_name".into(), json!(v.full_name));
            if v.full_name.is_some() {
                m.insert(
                    "full_name_basis".into(),
                    json!(
                        "Descriptor 2 of the V value. No account in the reference hive this \
                         decoder was established against carries a full name, so the slot's \
                         assignment could not be corroborated there; the value is offered as \
                         stored."
                    ),
                );
            }
            m.insert("comment".into(), json!(v.comment));
            m.insert(
                "stored_password_hash_present".into(),
                json!(v.nt_hash_material_present),
            );
            m.insert(
                "stored_lm_hash_present".into(),
                json!(v.lm_hash_material_present),
            );
            m.insert(
                "stored_password_hash_basis".into(),
                json!(
                    "Read from the DECLARED LENGTH of the V value's hash descriptor, never from \
                     its bytes: a blob of four bytes is the header with no material after it, \
                     which is an account with no stored hash rather than a hash this build could \
                     not read. No hash material appears on this record."
                ),
            );
            m.insert(
                "security_descriptor_bytes".into(),
                json!(v.security_descriptor_bytes),
            );
            m.insert(
                "v_descriptors".into(),
                json!(v
                    .descriptors
                    .iter()
                    .enumerate()
                    .map(|(slot, d)| json!({
                        "slot": slot,
                        "offset": d.offset,
                        "length": d.length,
                        "third_word": d.third_word,
                    }))
                    .collect::<Vec<_>>()),
            );
            if !v.out_of_bounds.is_empty() {
                m.insert("v_descriptors_refused".into(), json!(v.out_of_bounds));
                m.insert("content_incomplete".into(), json!(true));
                m.insert(
                    "content_incomplete_reason".into(),
                    json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
                );
            }
        }

        // Where the name came from. Two routes agreeing is worth stating; one
        // route alone is worth stating too, for the opposite reason.
        m.insert(
            "username_basis".into(),
            json!(match (
                self.v.as_ref().and_then(|v| v.username.as_deref()),
                self.name_from_index.as_deref(),
            ) {
                (Some(a), Some(b)) if a == b =>
                    "the V value's name descriptor and the Users\\Names key agree".to_string(),
                (Some(a), Some(b)) => format!(
                    "the V value's name descriptor says {a:?} and the Users\\Names key says \
                     {b:?}. They disagree; the V value is reported and the disagreement is \
                     stated rather than resolved."
                ),
                (Some(_), None) =>
                    "the V value's name descriptor. The Users\\Names index was not reached, so \
                     there is no second route to compare it against."
                        .to_string(),
                (None, Some(_)) =>
                    "the Users\\Names key component. The V value's name descriptor was not read."
                        .to_string(),
                (None, None) => "neither the V value nor the Users\\Names index yielded a name \
                                 for this RID."
                    .to_string(),
            }),
        );
        m.insert("key_path".into(), json!(self.key_path));
        m.insert("key_last_written".into(), json!(self.key_last_written));
        m.insert(
            "key_last_written_scope".into(),
            json!("the account's own SAM key"),
        );
        Value::Object(m)
    }
}

/// The bytes a descriptor names, or `None` -- with the reason recorded -- when
/// it does not lie inside the value.
///
/// A zero length is an absence and is **not** an error: see the module comment
/// for what happens to a reader that resolves the offset anyway.
fn descriptor_slice<'a>(
    bytes: &'a [u8],
    descriptors: &[VDescriptor],
    slot: usize,
    refused: &mut Vec<String>,
) -> Option<&'a [u8]> {
    let d = descriptors.get(slot)?;
    if d.length == 0 {
        return None;
    }
    let start = V_PAYLOAD_BASE.checked_add(d.offset as usize)?;
    let end = start.checked_add(d.length as usize)?;
    match bytes.get(start..end) {
        Some(s) => Some(s),
        None => {
            refused.push(format!(
                "descriptor {slot} declares offset {} and length {}, which ends at byte {} of a \
                 {}-byte V value. Nothing was read from it: resolving the offset and reading to a \
                 terminator would return whatever follows the value.",
                d.offset,
                d.length,
                end,
                bytes.len()
            ));
            None
        }
    }
}

/// A UTF-16LE string a descriptor names, bounded by its declared length.
fn string_at(
    bytes: &[u8],
    descriptors: &[VDescriptor],
    slot: usize,
    what: &str,
    refused: &mut Vec<String>,
) -> Option<String> {
    let s = descriptor_slice(bytes, descriptors, slot, refused)?;
    if s.len() % 2 != 0 {
        refused.push(format!(
            "descriptor {slot} ({what}) declares {} bytes, an odd length for UTF-16. It was not \
             decoded: dropping the trailing byte would publish a string the value does not hold.",
            s.len()
        ));
        return None;
    }
    let units: Vec<u16> = s
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    let text = String::from_utf16_lossy(&units);
    (!text.is_empty()).then_some(text)
}

/// A recorded time, or the sentence saying there is none.
fn time_or_reason(filetime: Option<u64>, did_what: &str) -> (Value, Option<String>) {
    match filetime {
        Some(0) => (
            Value::Null,
            Some(format!(
                "Not recorded: this field is zero in the account's F value, which is what Windows \
                 leaves when the account has never {did_what}. It is reported as no date rather \
                 than as 1601-01-01."
            )),
        ),
        Some(ft) => match seance_core::time::filetime_to_rfc3339(ft) {
            Some(t) => (json!(t), None),
            None => (
                Value::Null,
                Some(format!(
                    "Not recorded: this field holds 0x{ft:016X}, which is not a time this build \
                     will render -- before the Unix epoch, or one of the far-future values \
                     Windows uses to mean never. No date is claimed for it."
                )),
            ),
        },
        None => (Value::Null, None),
    }
}

/// Turn the walk's capture into one record per local account.
///
/// The name index is read first, so an account whose `V` value does not yield
/// a name still has one — and so the two routes can be compared where both
/// are present.
pub fn emit(capture: &crate::resident::ResidentCapture) -> Vec<Value> {
    use crate::resident::Anchor;
    use std::collections::BTreeMap;

    // RID -> name, from `Users\Names\<name>`. The RID travels in the default
    // value's TYPE field with zero bytes of data, so a reader that takes the
    // data gets nothing.
    let mut names: BTreeMap<u32, String> = BTreeMap::new();
    for key in capture.keys_matching(|a| matches!(a, Anchor::SamUserName { .. })) {
        let Anchor::SamUserName { name } = &key.anchor else {
            continue;
        };
        for v in &key.values {
            if let Some(seance_hive::KeyValueDataType::Unknown(rid)) = v.data_type {
                names.insert(rid, name.clone());
            }
        }
    }

    let mut out = Vec::new();
    for key in capture.keys_matching(|a| matches!(a, Anchor::SamUser { .. })) {
        let Anchor::SamUser { rid_hex } = &key.anchor else {
            continue;
        };
        let f_bytes = key
            .values
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case("F"))
            .map(|v| v.data.as_slice());
        let f = f_bytes.and_then(FValue::parse);
        let f_len_seen = f_bytes.map(<[u8]>::len).unwrap_or(0);
        let from_index = rid_from_key_name(rid_hex)
            .and_then(|rid| names.get(&rid))
            .cloned();

        let mut account = LocalAccount::new(rid_hex, f, from_index.as_deref(), f_len_seen);
        if let Some(v) = key
            .values
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case("V"))
            .and_then(|v| VValue::parse(&v.data))
        {
            account = account.with_v(v);
        }
        account.key_path = Some(key.key_path.clone());
        account.key_last_written =
            seance_core::time::filetime_to_rfc3339(key.last_written_filetime);
        out.push(account.to_json());
    }

    // A name in the index with no account key beneath `Users`. The index and
    // the account keys are two populations, and a name present in one and not
    // the other is a fact about the hive rather than a reason to fall silent.
    let accounted: std::collections::BTreeSet<u32> = capture
        .keys_matching(|a| matches!(a, Anchor::SamUser { .. }))
        .filter_map(|k| match &k.anchor {
            Anchor::SamUser { rid_hex } => rid_from_key_name(rid_hex),
            _ => None,
        })
        .collect();
    for (rid, name) in &names {
        if accounted.contains(rid) {
            continue;
        }
        out.push(json!({
            "type": "LocalAccount",
            "name": name,
            "username": name,
            "rid": rid,
            "username_basis": "the Users\\Names key component",
            "account_key_note": format!(
                "This account is in the SAM name index as {name:?} with RID {rid}, and the walk \
                 reached no Users\\{rid:08X} key holding its F and V values. None of its times, \
                 its account-control flags or its stored-hash state were read -- not because they \
                 are absent from the account, but because the key that holds them was not read \
                 here."
            ),
            "content_incomplete": true,
            "content_incomplete_reason":
                seance_core::io::IncompleteReason::UnresolvedStructure.as_str(),
        }));
    }
    out
}
