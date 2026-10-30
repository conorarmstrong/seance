#![forbid(unsafe_code)]
//! macOS behavioural and provenance artifacts.
//!
//! Séance already reconstructs the macOS filesystem layer (APFS/HFS+, FSEvents,
//! `.DS_Store`) and parses generic plists and SQLite databases. This crate adds
//! the *semantic* decoders for the behavioural artifacts an examiner actually
//! asks about — where a file came from, what an app was allowed to touch, what
//! runs at login, where the machine has been — that a raw row/key dump does not
//! answer:
//!
//! - [`QuarantineParser`] — `LSQuarantineEventsV2`: download provenance.
//! - [`TccParser`] — `TCC.db`: privacy permission grants.
//! - [`LaunchdPersistenceParser`] — `LaunchAgents`/`LaunchDaemons` autostart.
//! - [`WifiKnownNetworksParser`] — joined Wi-Fi networks and when.
//! - [`InstallHistoryParser`] — `InstallHistory.plist`: software installs.
//! - [`KnowledgeCParser`] — `knowledgeC.db`: the app-usage activity timeline.
//! - [`NotificationsParser`] — user notification history.
//! - [`AppleMailParser`] — `Envelope Index`: Mail's own index of every message
//!   it has seen. An index, not the mail: no bodies, and it says so.
//! - [`AslParser`] — `/var/log/asl/*.asl`: the Apple System Log store, which
//!   is **where macOS's `wtmpx` went**. Every boot, shutdown, console login,
//!   logout and SSH session with the address it came from, under the
//!   `com.apple.system.utmpx` and `com.apple.system.lastlog` facilities.
//! - [`KeychainParser`] — `login.keychain-db` / `System.keychain`: an
//!   encrypted store with a **cleartext index**. Which services and accounts
//!   the person held credentials for, and since when, without a password —
//!   and every secret reported as locked rather than absent.
//! - [`DataProtectionKeychainParser`] — `keychain-2.db`: the iOS-style
//!   keychain macOS also keeps. It names **no account and no service** — every
//!   such attribute is a SHA-1 — but it names the application that owns each
//!   secret, the protection class, and every device the Apple ID's keychain
//!   circle has held.
//! - [`OpenBsmParser`] — `/var/audit/*`: the login, authentication and
//!   administration history macOS keeps, which is where the answer to "who
//!   logged in last Tuesday, and who tried and failed" lives. `utmpx` holds
//!   only the sessions open at acquisition time; there is no macOS `btmp`.
//!
//! Each is a [`seance_core::module::ForensicsModule`] that self-selects by
//! filename, reads its input in full, never panics on malformed data, and states
//! incompleteness explicitly rather than presenting a partial read as complete.

mod asl;
mod bom;
mod firehose;
mod install_history;
mod keychain;
mod keychain2;
pub mod keychain_unlock;
mod knowledgec;
mod launchd;
mod mail;
mod notifications;
mod openbsm;
mod quarantine;
mod spotlight;
mod tcc;
mod timesync;
mod tracev3;
mod unifiedlog_chunks;
mod unifiedlog_decode;
mod unifiedlog_dumps;
mod unifiedlog_resolve;
mod uuidtext;
mod wifi;
pub use asl::AslParser;
pub use bom::BomParser;
pub use install_history::InstallHistoryParser;
pub use keychain::{
    decrypt_item_secrets, unlock_keychain, unlock_keychain_with_system_key, DecryptedSecret,
    ItemKind, KeychainParser, KeychainUnlock, SecretDecryption,
};
pub use keychain2::DataProtectionKeychainParser;
pub use keychain_unlock::UnlockError;
pub use knowledgec::KnowledgeCParser;
pub use launchd::LaunchdPersistenceParser;
pub use mail::AppleMailParser;
pub use notifications::NotificationsParser;
pub use openbsm::{AuditRecord, EventClass, Identity, OpenBsmParser, RecordFlaw, Subject};
pub use quarantine::QuarantineParser;
pub use spotlight::SpotlightStoreParser;
pub use tcc::TccParser;
pub use timesync::UnifiedLogTimesyncParser;
pub use tracev3::UnifiedLogParser;
pub use uuidtext::UnifiedLogCatalogueParser;
pub use wifi::WifiKnownNetworksParser;

/// Fuzzing entry for the unified-log parts a byte-only source never reaches:
/// the oversize, statedump and simpledump parsers, the Header chunk reader and the printf renderer
/// (they run only when a `.tracev3` can climb to its tree). Not an API.
#[doc(hidden)]
pub fn fuzz_unifiedlog_parts(data: &[u8]) {
    let items = firehose::parse_oversize(data)
        .map(|o| o.items)
        .unwrap_or_default();
    let _ = unifiedlog_decode::parse_header(data);
    let _ = unifiedlog_dumps::parse_statedump(data);
    let _ = unifiedlog_dumps::parse_simpledump(data);
    let format = String::from_utf8_lossy(data);
    let _ = unifiedlog_resolve::render(&format, &items);
}

/// Largest database this crate will spill to a temp file and open. macOS
/// behavioural DBs are small (MBs); a cap keeps a corrupt size field from
/// staging an unbounded file.
pub(crate) const MAX_DB_BYTES: u64 = 512 * 1024 * 1024;

/// Seconds between the Unix epoch (1970-01-01) and the Cocoa/CFAbsoluteTime
/// epoch (2001-01-01), both UTC.
pub(crate) const CF_EPOCH_OFFSET: i64 = 978_307_200;

/// Convert a Cocoa `CFAbsoluteTime` (seconds since 2001-01-01 UTC, as macOS
/// stores most timestamps) to Unix seconds plus the sub-second nanoseconds.
///
/// The fraction is kept because these columns are REAL and the sub-second part
/// is real evidence: quarantine downloads, knowledgeC activity bounds and
/// notification deliveries inside the same second order arbitrarily once it is
/// discarded, and a re-derived timestamp then disagrees with the source.
///
/// The whole part is FLOORED rather than cast, because `as i64` truncates
/// toward zero: on a pre-2001 (negative) value that moves the event *later* in
/// time, which is the direction that invents activity after an event of
/// interest rather than before it.
pub(crate) fn cfabsolute_to_unix_parts(cf: f64) -> Option<(i64, u32)> {
    if !cf.is_finite() {
        return None;
    }
    let whole = cf.floor();
    // Outside i64 the float-to-int cast saturates, which would report a date at
    // the end of time as fact. A value that far out is a misread column.
    if whole < i64::MIN as f64 || whole >= i64::MAX as f64 {
        return None;
    }
    let secs = (whole as i64).checked_add(CF_EPOCH_OFFSET)?;
    // f64 cannot represent every nanosecond, so a fraction within half a
    // nanosecond of the next second rounds to a full 1e9 and must carry.
    let nanos = ((cf - whole) * 1e9).round() as i64;
    if nanos >= 1_000_000_000 {
        return secs.checked_add(1).map(|s| (s, 0));
    }
    Some((secs, nanos.max(0) as u32))
}

/// Unix nanoseconds for a `(seconds, nanos)` pair, or `None` when there is no
/// sub-second part to preserve — the whole-seconds field already says it all.
pub(crate) fn unix_ns(secs: i64, nanos: u32) -> Option<i64> {
    if nanos == 0 {
        return None;
    }
    secs.checked_mul(1_000_000_000)?.checked_add(nanos as i64)
}

/// RFC3339 string for a Unix-seconds value, or `None` if out of range.
pub(crate) fn to_rfc3339(secs: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(secs, 0).map(|dt| dt.to_rfc3339())
}

/// RFC3339 string keeping the sub-second part, so the string an examiner reads
/// does not round away precision the record itself carries.
pub(crate) fn to_rfc3339_nanos(secs: i64, nanos: u32) -> Option<String> {
    chrono::DateTime::from_timestamp(secs, nanos).map(|dt| dt.to_rfc3339())
}

/// The final `/`-separated component of a path-like name, lowercased for
/// case-insensitive filename matching.
pub(crate) fn basename_lower(name: &str) -> String {
    name.rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_lowercase()
}

/// Stamp one of the standard incompleteness pairs (`content`, `inventory`) from
/// a list of reasons, returning the sentence written to `<prefix>_incomplete_detail`.
///
/// Several soft failures can fire on one record while the pair holds a single
/// machine token, so the first reason names the class and the detail carries
/// every sentence. Dropping the rest would leave an examiner reading
/// `cap_reached` with no hint that the framing broke as well.
pub(crate) fn stamp_incomplete(
    meta: &mut serde_json::Map<String, serde_json::Value>,
    prefix: &str,
    reasons: &[(seance_core::io::IncompleteReason, String)],
) -> Option<String> {
    let (reason, _) = reasons.first()?;
    let detail = reasons
        .iter()
        .map(|(_, sentence)| sentence.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    meta.insert(format!("{prefix}_incomplete"), serde_json::json!(true));
    meta.insert(
        format!("{prefix}_incomplete_reason"),
        serde_json::json!(reason.as_str()),
    );
    meta.insert(
        format!("{prefix}_incomplete_detail"),
        serde_json::json!(detail),
    );
    Some(detail)
}

/// Bytes staged in memory for a parser, and whether they are the whole file.
///
/// A parser that saw less than the file declares — because a byte cap stopped
/// the read, or because the source ran out — can only produce a partial answer.
/// The shortfall therefore travels with the bytes, because the two ways it
/// escapes are both silent: a prefix that parses is emitted as a finished
/// record, and a prefix that does not parse makes the file vanish from the case
/// entirely.
pub(crate) struct Staged {
    /// What was actually delivered, truncated to that length.
    pub(crate) bytes: Vec<u8>,
    /// Size the data source declared.
    pub(crate) declared: u64,
    /// Bytes actually delivered.
    pub(crate) got: u64,
    /// True when the byte cap, not the file, decided where the read stopped.
    pub(crate) capped: bool,
}

impl Staged {
    /// Read `ds` from offset 0, up to `cap` bytes.
    pub(crate) fn read(ds: &dyn seance_core::data_source::DataSource, cap: u64) -> Self {
        let declared = ds.size();
        let mut bytes = vec![0u8; declared.min(cap) as usize];
        let got = seance_core::io::read_full(ds, 0, &mut bytes) as u64;
        bytes.truncate(got as usize);
        Self {
            bytes,
            declared,
            got,
            capped: declared > cap,
        }
    }

    /// Why the staged bytes are not the whole file, or `None` when they are.
    pub(crate) fn incomplete_reason(&self) -> Option<seance_core::io::IncompleteReason> {
        if self.got >= self.declared {
            return None;
        }
        Some(if self.capped {
            seance_core::io::IncompleteReason::CapReached
        } else {
            seance_core::io::IncompleteReason::ShortRead
        })
    }

    /// The sentence an examiner reads: how much of the file was actually parsed.
    pub(crate) fn detail(&self, what: &str) -> String {
        format!(
            "{} of the {} bytes {what} declares were staged, so anything past that offset was \
             not parsed",
            self.got, self.declared
        )
    }

    /// Stamp the content-incompleteness pair when the read fell short.
    pub(crate) fn stamp(
        &self,
        what: &str,
        meta: &mut serde_json::Map<String, serde_json::Value>,
    ) -> bool {
        match self.incomplete_reason() {
            Some(reason) => {
                stamp_incomplete(meta, "content", &[(reason, self.detail(what))]).is_some()
            }
            None => false,
        }
    }

    /// The record that says a file was never staged in full, for the case where
    /// the partial bytes produced no records at all.
    ///
    /// Without it the file simply disappears: a known-networks plist or a
    /// LaunchAgent whose prefix will not parse leaves no record and no flag,
    /// which reads exactly like a machine that had neither.
    pub(crate) fn incomplete_marker(
        &self,
        case_id: uuid::Uuid,
        parent_id: uuid::Uuid,
        record_type: &str,
        file_name: &str,
        what_was_lost: &str,
    ) -> Option<seance_core::artifact::Artifact> {
        let reason = self.incomplete_reason()?;
        let mut meta = serde_json::Map::new();
        meta.insert("type".into(), serde_json::json!(record_type));
        meta.insert("subtype".into(), serde_json::json!("parse_incomplete"));
        meta.insert("file_name".into(), serde_json::json!(file_name));
        meta.insert("status".into(), serde_json::json!("NotStagedInFull"));
        meta.insert("bytes_staged".into(), serde_json::json!(self.got));
        meta.insert("bytes_declared".into(), serde_json::json!(self.declared));
        let detail = format!("{}; {what_was_lost}", self.detail(file_name));
        let _ = stamp_incomplete(&mut meta, "content", &[(reason, detail.clone())]);
        meta.insert(
            "name".into(),
            serde_json::json!(format!("{file_name}: incomplete — {detail}")),
        );
        Some(
            seance_core::artifact::Artifact::new(
                case_id,
                seance_core::artifact::ArtifactType::ParsedRecord,
                None,
                meta.into(),
            )
            .with_parent(parent_id)
            .with_subtype("parse_incomplete"),
        )
    }

    /// The record that says a file this reader selected could not be read,
    /// whether or not it was staged in full.
    ///
    /// Where the read fell short, that is the likelier cause and
    /// [`Staged::incomplete_marker`] says so. Where the whole file was staged
    /// and still did not yield what this reader looks for, the file itself is
    /// the problem — damaged, or a layout this reader does not know — and
    /// returning nothing would read as a file that recorded nothing (HUNT-179).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn unreadable_marker(
        &self,
        case_id: uuid::Uuid,
        parent_id: uuid::Uuid,
        record_type: &str,
        file_name: &str,
        status: &str,
        why: &str,
        what_was_lost: &str,
    ) -> seance_core::artifact::Artifact {
        if let Some(marker) =
            self.incomplete_marker(case_id, parent_id, record_type, file_name, what_was_lost)
        {
            return marker;
        }
        let mut meta = serde_json::Map::new();
        meta.insert("type".into(), serde_json::json!(record_type));
        meta.insert("subtype".into(), serde_json::json!("parse_incomplete"));
        meta.insert("file_name".into(), serde_json::json!(file_name));
        meta.insert("status".into(), serde_json::json!(status));
        meta.insert("bytes_staged".into(), serde_json::json!(self.got));
        meta.insert("bytes_declared".into(), serde_json::json!(self.declared));
        let detail = format!("{file_name} was read in full and {why}, {what_was_lost}");
        let _ = stamp_incomplete(
            &mut meta,
            "content",
            &[(
                seance_core::io::IncompleteReason::UnresolvedStructure,
                detail.clone(),
            )],
        );
        meta.insert(
            "name".into(),
            serde_json::json!(format!("{file_name}: not read — {detail}")),
        );
        seance_core::artifact::Artifact::new(
            case_id,
            seance_core::artifact::ArtifactType::ParsedRecord,
            None,
            meta.into(),
        )
        .with_parent(parent_id)
        .with_subtype("parse_incomplete")
    }
}

/// True if the staged file begins with the SQLite 3 header. A file that does not
/// is not our database, and the caller should stay silent rather than report a
/// parse failure for something that was never the target.
pub(crate) fn staged_looks_like_sqlite(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut header = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut header))
        .map(|_| &header == b"SQLite format 3\0")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfabsolute_time_keeps_its_sub_second_part() {
        // A real LSQuarantine/knowledgeC REAL column: half a second past the
        // whole second. Truncating it loses the ordering of two events inside
        // the same second.
        let (secs, nanos) = cfabsolute_to_unix_parts(700_000_000.5).expect("a real timestamp");
        assert_eq!(secs, 700_000_000 + CF_EPOCH_OFFSET);
        assert_eq!(nanos, 500_000_000);
        assert_eq!(
            unix_ns(secs, nanos),
            Some((700_000_000 + CF_EPOCH_OFFSET) * 1_000_000_000 + 500_000_000)
        );
        assert_eq!(
            to_rfc3339_nanos(secs, nanos).unwrap(),
            "2023-03-08T20:26:40.500+00:00"
        );
    }

    #[test]
    fn a_whole_second_carries_no_sub_second_field_or_fraction() {
        let (secs, nanos) = cfabsolute_to_unix_parts(700_000_000.0).unwrap();
        assert_eq!(nanos, 0);
        assert_eq!(unix_ns(secs, nanos), None, "nothing to preserve");
        assert_eq!(
            to_rfc3339_nanos(secs, nanos).unwrap(),
            "2023-03-08T20:26:40+00:00"
        );
    }

    #[test]
    fn pre_2001_cfabsolute_time_floors_instead_of_moving_the_event_later() {
        // `cf as i64` truncates toward zero, which would report this half-second
        // before the Cocoa epoch as the epoch itself — later than it happened.
        let (secs, nanos) = cfabsolute_to_unix_parts(-0.5).unwrap();
        assert_eq!(secs, CF_EPOCH_OFFSET - 1);
        assert_eq!(nanos, 500_000_000);
    }

    #[test]
    fn non_finite_and_out_of_range_cfabsolute_time_stays_absent() {
        assert_eq!(cfabsolute_to_unix_parts(f64::NAN), None);
        assert_eq!(cfabsolute_to_unix_parts(f64::INFINITY), None);
        assert_eq!(cfabsolute_to_unix_parts(1e30), None);
    }
}
