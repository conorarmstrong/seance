//! Synthetic encrypted iOS backups, for this crate's tests and — behind the
//! `test-support` feature — for other crates' integration tests (`SEC-204`:
//! the credential route's end-to-end leak test in `seance_api`).
//!
//! A synthetic backup pins a **mechanism** — how a password reaches the parser,
//! what it reports, where the secret does and does not go. It is built with the
//! same key-derivation code the parser uses, so it is not validation of the
//! decryption against a real device's backup.

use crate::crypto;
use std::path::PathBuf;
use uuid::Uuid;

/// Protection class used throughout the synthetic encrypted backup.
pub const FIXTURE_CLASS: u32 = 3;

/// How a synthetic manifest entry states its per-file key and protection class.
///
/// iOS states the class twice — as `ProtectionClass` in the metadata blob and as
/// a 4-byte little-endian prefix on the wrapped key — and real backups are not
/// guaranteed to give both.
pub enum KeyShape {
    /// Both carriers present.
    ClassFieldAndKey,
    /// A prefixed key, but no `ProtectionClass` field: the case that used to
    /// default the class to 0 and route ciphertext out as file content.
    KeyOnlyNoClassField,
    /// `EncryptionKey` present but its `NS.data` holds only the 4-byte class
    /// prefix — no wrapped key at all.
    TruncatedKeyBlob,
    /// No `EncryptionKey` entry.
    NoKey,
}

/// Build a TLV entry: 4-byte tag (BE) + 4-byte length (BE) + value.
pub fn tlv(tag: &[u8; 4], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(tag);
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// AES-256-CBC with a zero IV over PKCS#7-padded plaintext — the shape iOS uses
/// for both `Manifest.db` and the individual backup files.
pub fn aes_cbc_encrypt_pkcs7(key: [u8; 32], plaintext: &[u8]) -> Vec<u8> {
    use aes::Aes256;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    let pad = 16 - (plaintext.len() % 16);
    let mut buf = plaintext.to_vec();
    buf.extend(std::iter::repeat_n(pad as u8, pad));

    let cipher = Aes256CbcEnc::new(&key.into(), &[0u8; 16].into());
    let n = buf.len();
    cipher
        .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, n)
        .unwrap();
    buf
}

/// The NSKeyedArchiver `file` BLOB that `Manifest.db` stores per entry.
pub fn metadata_blob(size: usize, shape: &KeyShape, wrapped_key: &[u8]) -> Vec<u8> {
    let int = |v: i64| plist::Value::Integer(plist::Integer::from(v));

    let mut root = plist::Dictionary::new();
    root.insert("Size".into(), int(size as i64));
    root.insert("Mode".into(), int(0o100644));
    root.insert("LastModified".into(), int(1_700_000_000));
    root.insert("Birth".into(), int(1_690_000_000));
    root.insert("InodeNumber".into(), int(4242));
    root.insert("UserID".into(), int(501));
    root.insert("GroupID".into(), int(501));

    let mut ns_data = FIXTURE_CLASS.to_le_bytes().to_vec();
    ns_data.extend_from_slice(wrapped_key);

    let mut enc_obj = plist::Dictionary::new();
    match shape {
        KeyShape::ClassFieldAndKey => {
            root.insert("ProtectionClass".into(), int(FIXTURE_CLASS as i64));
            root.insert(
                "EncryptionKey".into(),
                plist::Value::Uid(plist::Uid::new(2)),
            );
            enc_obj.insert("NS.data".into(), plist::Value::Data(ns_data));
        }
        KeyShape::KeyOnlyNoClassField => {
            root.insert(
                "EncryptionKey".into(),
                plist::Value::Uid(plist::Uid::new(2)),
            );
            enc_obj.insert("NS.data".into(), plist::Value::Data(ns_data));
        }
        KeyShape::TruncatedKeyBlob => {
            root.insert("ProtectionClass".into(), int(FIXTURE_CLASS as i64));
            root.insert(
                "EncryptionKey".into(),
                plist::Value::Uid(plist::Uid::new(2)),
            );
            enc_obj.insert(
                "NS.data".into(),
                plist::Value::Data(FIXTURE_CLASS.to_le_bytes().to_vec()),
            );
        }
        KeyShape::NoKey => {
            root.insert("ProtectionClass".into(), int(FIXTURE_CLASS as i64));
        }
    }

    let mut top = plist::Dictionary::new();
    top.insert("root".into(), plist::Value::Uid(plist::Uid::new(1)));

    let mut archive = plist::Dictionary::new();
    archive.insert(
        "$archiver".into(),
        plist::Value::String("NSKeyedArchiver".into()),
    );
    archive.insert("$version".into(), int(100_000));
    archive.insert("$top".into(), plist::Value::Dictionary(top));
    archive.insert(
        "$objects".into(),
        plist::Value::Array(vec![
            plist::Value::String("$null".into()),
            plist::Value::Dictionary(root),
            plist::Value::Dictionary(enc_obj),
        ]),
    );

    let mut out = Vec::new();
    plist::Value::Dictionary(archive)
        .to_writer_binary(&mut out)
        .unwrap();
    out
}

/// Build a complete synthetic **encrypted** iOS backup on disk: keybag in
/// `Manifest.plist`, an AES-encrypted `Manifest.db`, and one AES-encrypted blob
/// per file. Returns the directory and the backup password.
///
/// Each entry is `(file_id, relative_path, manifest flags, plaintext, key
/// shape)`. Flag `0x4` marks a symlink, for which no stored blob is written —
/// a symlink's content is the target path in the manifest, and the backup keeps
/// no file for it.
pub fn build_encrypted_backup(files: &[(&str, &str, i64, &[u8], KeyShape)]) -> (PathBuf, String) {
    build_encrypted_backup_with(files, &[], |_| "HomeDomain")
}

/// [`build_encrypted_backup`] with extra passcode-wrapped class keys in the
/// keybag (`(class, key)`) and a manifest domain chosen per relative path —
/// what a synthetic `KeychainDomain/keychain-backup.plist` needs (HUNT-111).
pub fn build_encrypted_backup_with(
    files: &[(&str, &str, i64, &[u8], KeyShape)],
    extra_class_keys: &[(u32, [u8; 32])],
    domain_for: fn(&str) -> &'static str,
) -> (PathBuf, String) {
    use aes_kw::KekAes256;

    let password = "correct horse battery staple".to_string();
    let salt = [0xB1u8; 32];
    let class_key = [0x5Au8; 32];

    // The keybag's own parameters, used to derive the passcode key that wraps
    // the class key. iter = 1 keeps the test fast; the algorithm is unchanged.
    let derive_bag = crypto::Keybag {
        uuid: vec![],
        salt: salt.to_vec(),
        iter: 1,
        dpsl: None,
        dpic: None,
        class_keys: vec![],
    };
    let passcode_key = crypto::derive_passcode_key(&password, &derive_bag).unwrap();
    let wrapped_class_key = KekAes256::from(passcode_key).wrap_vec(&class_key).unwrap();

    let mut keybag = Vec::new();
    keybag.extend(tlv(b"UUID", &[0xA1u8; 16]));
    keybag.extend(tlv(b"SALT", &salt));
    keybag.extend(tlv(b"ITER", &1u32.to_be_bytes()));
    keybag.extend(tlv(b"CLAS", &FIXTURE_CLASS.to_be_bytes()));
    keybag.extend(tlv(b"WRAP", &2u32.to_be_bytes()));
    keybag.extend(tlv(b"WPKY", &wrapped_class_key));
    for (class, key) in extra_class_keys {
        keybag.extend(tlv(b"CLAS", &class.to_be_bytes()));
        keybag.extend(tlv(b"WRAP", &2u32.to_be_bytes()));
        keybag.extend(tlv(
            b"WPKY",
            &KekAes256::from(passcode_key).wrap_vec(key).unwrap(),
        ));
    }

    let dir = std::env::temp_dir().join(format!("seance_ios_encbackup_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();

    // The plaintext Manifest.db is built in a scratch directory so no sqlite
    // artefact is left inside the backup directory itself.
    let scratch = std::env::temp_dir().join(format!("seance_ios_encscratch_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&scratch).unwrap();
    let plain_db_path = scratch.join("Manifest.db");
    {
        let conn = rusqlite::Connection::open(&plain_db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, \
             relativePath TEXT, flags INTEGER, file BLOB);",
        )
        .unwrap();

        for (i, (file_id, rel, flags, plaintext, shape)) in files.iter().enumerate() {
            let file_id: &str = file_id;
            let rel: &str = rel;
            let flags: i64 = *flags;
            let plaintext: &[u8] = plaintext;

            let file_key = [0x20u8 + i as u8; 32];
            let wrapped = KekAes256::from(class_key).wrap_vec(&file_key).unwrap();
            let blob = metadata_blob(plaintext.len(), shape, &wrapped);

            conn.execute(
                "INSERT INTO Files (fileID, domain, relativePath, flags, file) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![file_id, domain_for(rel), rel, flags, blob],
            )
            .unwrap();

            // A symlink has no stored file in the backup at all.
            if flags & 0x4 != 0 {
                continue;
            }

            // The stored blob is always ciphertext: this backup is encrypted.
            let ciphertext = aes_cbc_encrypt_pkcs7(file_key, plaintext);
            let sub = dir.join(&file_id[..2]);
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::write(sub.join(file_id), &ciphertext).unwrap();
        }
        drop(conn);
    }

    let plain_db = std::fs::read(&plain_db_path).unwrap();
    let _ = std::fs::remove_dir_all(&scratch);

    let manifest_file_key = [0x11u8; 32];
    std::fs::write(
        dir.join("Manifest.db"),
        aes_cbc_encrypt_pkcs7(manifest_file_key, &plain_db),
    )
    .unwrap();

    let mut manifest_key = FIXTURE_CLASS.to_le_bytes().to_vec();
    manifest_key.extend_from_slice(
        &KekAes256::from(class_key)
            .wrap_vec(&manifest_file_key)
            .unwrap(),
    );

    let mut plist_dict = plist::Dictionary::new();
    plist_dict.insert("IsEncrypted".into(), plist::Value::Boolean(true));
    plist_dict.insert("Version".into(), plist::Value::String("10.0".into()));
    plist_dict.insert("BackupKeyBag".into(), plist::Value::Data(keybag));
    plist_dict.insert("ManifestKey".into(), plist::Value::Data(manifest_key));
    plist::Value::Dictionary(plist_dict)
        .to_file_xml(dir.join("Manifest.plist"))
        .unwrap();

    (dir, password)
}

/// The manifest `fileID` the synthetic keychain is stored under (the real
/// Hickman iOS 17 backup's, so a path-shaped test reads like the real one).
pub const KEYCHAIN_FILE_ID: &str = "51a4616e576dd33cd2abadfea874eb8ff246bf0e";

/// A synthetic encrypted backup whose `KeychainDomain/keychain-backup.plist`
/// holds two `genp` items with account `HomeNetwork`, service `AirPort` and
/// the secret `secret`: item 0 in class 7, which the backup's class key opens;
/// item 1 in class 10, wrapped under a key the backup does not carry, as a
/// `ThisDeviceOnly` item's is. Item `i`'s persistent reference is 20 bytes of
/// `i`. HUNT-111. Built with this crate's own GCM and key wrap: it pins the
/// mechanism, it is not validation.
pub fn build_keychain_backup(secret: &[u8]) -> (PathBuf, String) {
    use crate::keychain_backup::fixture;
    const K7: [u8; 32] = [0x77; 32];
    const K10: [u8; 32] = [0x1A; 32];
    let attrs = fixture::attributes(&[
        ("agrp", b"apple"),
        ("acct", b"HomeNetwork"),
        ("svce", b"AirPort"),
        ("v_Data", secret),
    ]);
    let open_item = fixture::v_data(7, &K7, &[0x31; 32], &attrs);
    let bound_item = fixture::v_data(10, &[0xDE; 32], &[0x32; 32], &attrs);
    let plist = fixture::plist(&[("genp", vec![open_item, bound_item])]);
    build_encrypted_backup_with(
        &[(
            KEYCHAIN_FILE_ID,
            "keychain-backup.plist",
            1,
            &plist,
            KeyShape::ClassFieldAndKey,
        )],
        &[(7, K7), (10, K10)],
        |rel| {
            if rel == "keychain-backup.plist" {
                "KeychainDomain"
            } else {
                "HomeDomain"
            }
        },
    )
}
