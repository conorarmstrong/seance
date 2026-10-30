//! The validation stamp every record this crate emits carries — one per
//! format, because the two formats have met different evidence.
//!
//! Modelled on `seance_plugin_memory_macos::unvalidated`, deliberately: this
//! project has one shape for "the code is written and has never met the
//! evidence", and a second shape would be a second thing for a reader to learn.
//!
//! * **`plum.sqlite`** (Windows 10 Anniversary and later) was compared on
//!   2026-09-27 against one **lab-made** database written by Sticky Notes
//!   6.1.4.0 (`PLUM-1` in `documentation/VALIDATION.md`), whose schema is
//!   `PRAGMA user_version` 13. A record from a store at `user_version` 13
//!   carries a stamp saying exactly that; a record from any other version, or
//!   from a store whose version could not be read, keeps the never-validated
//!   stamp. The app version is not written in the file, so the stamp is keyed
//!   on the one thing the file does say. [`stamp_plum`] is the only way a
//!   `plum.sqlite` record is stamped.
//! * **`StickyNotes.snt`** was compared on 2026-09-24 against one real
//!   Windows 7 file (`SNT-1` in `documentation/VALIDATION.md`), so its records
//!   carry a stamp that says exactly that much and no more.

use serde_json::{json, Map, Value};

/// Wire value of `validation_state`. A sentence-shaped key rather than
/// `"none"`, because it is read by a human in a report column and "none"
/// invites the reading "no problems".
pub const VALIDATION_STATE: &str = "never_validated_against_real_notes";

/// What the `plum.sqlite` reader was built from, in place of evidence.
pub const VALIDATION_BASIS: &str =
    "the documented structure of plum.sqlite, and the one lab-made database compared in PLUM-1 \
     (documentation/VALIDATION.md), which is user_version 13; this store's schema version is not \
     13, or could not be read, so no known answer covers it. No seized or public plum.sqlite has \
     been found: the LocalState directories of the LoneWolf, DFIR Madness Case 001 desktop and \
     BelkaCTF 6 Windows images are all empty";

/// The sentence an examiner reads on a `plum.sqlite` record whose schema
/// version is not the validated one.
pub const VALIDATION_NOTICE: &str =
    "This record comes from a plum.sqlite whose schema version is not the one this parser has \
     been compared against. Only user_version 13 (written by Sticky Notes 6.1.4.0, compared \
     against one lab-made database) has been checked; this store's schema has NEVER been run \
     against a known answer. Treat every value here as unverified: it may be correct, and \
     nothing in this tool has established that it is. Do not rely on it in a report without \
     independent corroboration.";

/// The `PRAGMA user_version` of the one `plum.sqlite` schema that has been
/// compared against a known answer (`PLUM-1`).
pub const PLUM_VALIDATED_USER_VERSION: i64 = 13;

/// Wire value of `validation_state` on a `plum.sqlite` record from a store at
/// [`PLUM_VALIDATED_USER_VERSION`].
pub const PLUM_VALIDATION_STATE: &str = "plum_validated_against_one_lab_made_database";

/// What the `plum.sqlite` reader was compared against.
pub const PLUM_VALIDATION_BASIS: &str =
    "PLUM-1 in documentation/VALIDATION.md: one LAB-MADE plum.sqlite, written on 2026-09-27 by \
     the real Microsoft Sticky Notes app 6.1.4.0 on the project's own Windows 11 25H2 lab VM \
     (build 26200), PRAGMA user_version 13, in three copies (app running before a delete, app \
     running after it, app closed). Every live note's Id, rowid, text (with and without the \
     paragraph ids), CreatedAt and UpdatedAt, and the deleted note recovered from the \
     write-ahead log with its frame number, agreed with the ground truth recorded as the notes \
     were made. It is not a public or real-world image";

/// The sentence an examiner reads on a `plum.sqlite` record at `user_version` 13.
pub const PLUM_VALIDATION_NOTICE: &str =
    "The plum.sqlite reader has been checked against one lab-made database written by Sticky \
     Notes 6.1.4.0 (schema user_version 13) on a Windows 11 25H2 test machine, and agreed with \
     that database's known answer. The evidence is lab-made, not seized. The file does not \
     record which app version wrote it, so a user_version 13 store written by another version \
     is read by the same code and has not been compared; stores at any other user_version are \
     unvalidated and say so. Ink, images, sync fields and the other tables have not been \
     compared against a known answer.";

/// Wire value of `validation_state` on a `StickyNotes.snt` record.
pub const SNT_VALIDATION_STATE: &str = "snt_validated_against_one_real_file";

/// What the `.snt` reader was compared against.
pub const SNT_VALIDATION_BASIS: &str =
    "SNT-1 in documentation/VALIDATION.md: one real StickyNotes.snt written by Windows 7 (the \
     NIST CFReDS Data Leakage case), holding one note. The storage name, the note's text, the \
     storage's created and modified times, and every stream's name and length agreed with an \
     independent reading of the same file (7-Zip's compound-file listing, the RTF stream read \
     by hand, and the note's own UTF-16 plain-text stream)";

/// The sentence an examiner reads on a `.snt` record.
pub const SNT_VALIDATION_NOTICE: &str =
    "The StickyNotes.snt reader has been checked against one real Windows 7 file holding one \
     plain-text note, and agreed with an independent reading of it. A file with several notes, a \
     note with an embedded picture or rich formatting, and a file written by Windows 8 or by \
     Windows 10 before the Anniversary Update have not been met: values from those are read by \
     the same code and have not been compared against a known answer.";

/// The fields every `plum.sqlite` record carries.
pub fn unvalidated_stamp() -> Value {
    json!({
        "validation_state": VALIDATION_STATE,
        "validated_against_real_notes": false,
        "validation_basis": VALIDATION_BASIS,
        "validation_notice": VALIDATION_NOTICE,
    })
}

/// The fields a `plum.sqlite` record from a store at `user_version` 13 carries.
pub fn plum_validated_stamp() -> Value {
    json!({
        "validation_state": PLUM_VALIDATION_STATE,
        "validated_against_real_notes": true,
        "validation_evidence": "lab_made",
        "validated_app_version": "6.1.4.0",
        "validated_user_version": PLUM_VALIDATED_USER_VERSION,
        "validation_basis": PLUM_VALIDATION_BASIS,
        "validation_notice": PLUM_VALIDATION_NOTICE,
    })
}

/// Stamp a `plum.sqlite` record body — the single choke point for that format.
///
/// `user_version` is the store's `PRAGMA user_version` (`None` when it was not
/// recorded, would not read, or no database was opened). Only the validated
/// version earns the bounded stamp; everything else gets the never-validated
/// one. Overwrites, like [`stamp_unvalidated`], and removes the validated-only
/// keys first so a record cannot carry a mixture of the two.
pub fn stamp_plum(object: &mut Map<String, Value>, user_version: Option<i64>) {
    for key in [
        "validation_evidence",
        "validated_app_version",
        "validated_user_version",
    ] {
        object.remove(key);
    }
    let stamp = if user_version == Some(PLUM_VALIDATED_USER_VERSION) {
        plum_validated_stamp()
    } else {
        unvalidated_stamp()
    };
    for (key, value) in stamp.as_object().expect("the stamps are object literals") {
        object.insert(key.clone(), value.clone());
    }
}

/// The fields every `StickyNotes.snt` record carries.
pub fn snt_stamp() -> Value {
    json!({
        "validation_state": SNT_VALIDATION_STATE,
        "validated_against_real_notes": true,
        "validation_basis": SNT_VALIDATION_BASIS,
        "validation_notice": SNT_VALIDATION_NOTICE,
    })
}

/// Stamp a `StickyNotes.snt` record. Overwrites, like [`stamp_unvalidated`].
pub fn stamp_snt(object: &mut Map<String, Value>) {
    for (key, value) in snt_stamp()
        .as_object()
        .expect("snt_stamp is an object literal")
    {
        object.insert(key.clone(), value.clone());
    }
}

/// Stamp the never-validated marker onto a `plum.sqlite` record body.
///
/// Overwrites rather than merges: a stage that had somehow set one of these
/// keys itself must not be able to weaken the marker.
pub fn stamp_unvalidated(object: &mut Map<String, Value>) {
    for (key, value) in unvalidated_stamp()
        .as_object()
        .expect("unvalidated_stamp is an object literal")
    {
        object.insert(key.clone(), value.clone());
    }
}
