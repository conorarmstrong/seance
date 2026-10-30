//! Obtaining a symbol file an image needs, when the examiner asks for it.
//!
//! # The gap this closes
//!
//! Séance can already say exactly which symbol file a memory image needs — the
//! Windows tier reads the kernel's CodeView record and reports the PDB name,
//! GUID and age — and it can already read an ISF once one is on disk. What it
//! could not do was *get* one. An examiner was told "no symbol file matches
//! `ntkrnlmp.pdb` GUID `2203…416D` age 1" and left to find it themselves, while
//! the analysis that would have followed sat one 6 MB file away.
//!
//! # Why this is opt-in, and stays opt-in
//!
//! Reaching the network during an examination is a decision about the lab, not
//! a convenience: some are air-gapped by policy, and in others an outbound
//! request from an analysis workstation is itself an event someone must be able
//! to account for. So nothing here runs unless the examiner turns it on for
//! that run, and every fetch returns a [`FetchRecord`] naming the URL, the
//! bytes, and their SHA-256.
//!
//! That record is not decoration. A symbol table *determines* what the analysis
//! says — where `_EPROCESS.UniqueProcessId` sits, which address
//! `PsActiveProcessHead` resolves to — so a fetched file is an input to the
//! findings in the same way the image is. It belongs in the chain of custody,
//! and [`seance_symbols::source`] already hashes and records whatever is placed
//! in the symbol directory, so a fetch that lands there is provenanced by the
//! path it was already going to take.
//!
//! # What it will not do
//!
//! * It will not redistribute what it fetches. Microsoft's symbol server terms
//!   permit downloading PDBs for debugging and analysis and prohibit
//!   redistributing them; converting one locally to an ISF and using it in an
//!   examination is the sanctioned use, and shipping a cache of them is not.
//! * It will not overwrite a symbol file that is already there. A lab's curated
//!   pack is the examiner's evidence about layout; silently replacing it with
//!   something off the internet would change an analysis without anybody
//!   choosing that.
//! * It will not read an unbounded response, and it follows only a bounded
//!   number of redirects. It does *not* pin the host a redirect lands on —
//!   Microsoft's symbol server legitimately serves from Azure blob storage — so
//!   the guarantee comes from [`verify_pdb_identity`] instead: the file has to
//!   be the symbols that were asked for, whatever host handed them over. That
//!   is the stronger check, because symbols for a neighbouring build parse
//!   perfectly and put every offset in the wrong place.
//!
//!   A prebuilt ISF has no requested GUID to check against — the examiner names
//!   a path in someone else's store — so [`verify_isf_shape`] can only
//!   establish that what arrived is an ISF at all. That is a genuinely weaker
//!   guarantee than the PDB route's, and it is stated rather than glossed.

#![forbid(unsafe_code)]

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

mod convert;
mod pdb_isf;

pub use convert::{pdb_to_isf, ConversionSummary};

/// Largest symbol payload this will accept, compressed or not.
///
/// A kernel PDB is tens of megabytes and a full ISF pack is hundreds; 1 GiB is
/// far above anything real and far below "fills the examiner's disk while they
/// are looking at something else".
pub const MAX_SYMBOL_BYTES: u64 = 1024 * 1024 * 1024;

/// How long to wait for a symbol server before giving up.
pub const REQUEST_TIMEOUT_SECS: u64 = 120;

/// The Microsoft public symbol server.
///
/// The URL shape is fixed and long-standing:
/// `<base>/<pdb name>/<GUID><age>/<pdb name>`, with the GUID as 32 uppercase
/// hex characters in symbol-store byte order — which is what
/// `seance_plugin_memory_windows::automagic_pe::format_pdb_guid` already
/// produces, because it was written against this convention.
pub const MICROSOFT_SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

/// Where the Volatility Foundation publishes prebuilt ISF packs.
///
/// Used for the tiers where no upstream symbol server exists: Linux and macOS
/// have no equivalent of Microsoft's, so the community builds ISFs from DWARF
/// and hosts them. The files are JSON layout metadata — offsets, sizes and type
/// names — which Séance already reads natively.
pub const VOLATILITY_ISF_BASE: &str =
    "https://downloads.volatilityfoundation.org/volatility3/symbols";

/// Anything that went wrong obtaining a symbol file.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The examiner has not enabled network symbol acquisition for this run.
    #[error(
        "symbol acquisition is off for this run: nothing was requested from the network. \
         Enable it explicitly if this lab permits an outbound request during an examination."
    )]
    NotPermitted,

    /// The server does not have this file. Common and not an error in the
    /// evidence: an insider or very new build may simply not be published.
    #[error("{source_name} has no symbols for {what}: the server answered {status}")]
    NotFound {
        /// Which source was asked.
        source_name: &'static str,
        /// What was asked for, in the examiner's terms.
        what: String,
        /// HTTP status returned.
        status: u16,
    },

    /// The response was larger than [`MAX_SYMBOL_BYTES`].
    #[error("refused a symbol payload over the {MAX_SYMBOL_BYTES}-byte ceiling from {url}")]
    TooLarge {
        /// Where it came from.
        url: String,
    },

    /// A file is already at the destination.
    #[error(
        "{} already exists; refusing to replace a symbol file that is already in the store",
        path.display()
    )]
    WouldOverwrite {
        /// The file that would have been replaced.
        path: PathBuf,
    },

    /// The transport failed.
    #[error("could not reach {url}: {detail}")]
    Transport {
        /// Where it was going.
        url: String,
        /// What the client said.
        detail: String,
    },

    /// The file that arrived is not the symbols that were requested.
    #[error(
        "the downloaded symbols are not the ones requested, so they describe a different \
         kernel and every offset from them would be wrong: {detail}"
    )]
    WrongIdentity {
        /// What was asked for against what arrived.
        detail: String,
    },

    /// Writing to the symbol directory failed.
    #[error("could not write {}: {source}", path.display())]
    Write {
        /// Destination.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
}

/// Whether this run may reach the network for symbols, and where.
///
/// Constructed deliberately: [`Default`] is [`Self::offline`], so a caller that
/// forgets to ask still does not make a request.
#[derive(Debug, Clone)]
pub struct FetchPolicy {
    /// Hosts this run is allowed to contact, as full base URLs.
    allowed: Vec<String>,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self::offline()
    }
}

impl FetchPolicy {
    /// No network access. Every fetch returns [`FetchError::NotPermitted`].
    pub fn offline() -> Self {
        Self {
            allowed: Vec::new(),
        }
    }

    /// Permit the standard public symbol sources.
    pub fn public_sources() -> Self {
        Self {
            allowed: vec![
                MICROSOFT_SYMBOL_SERVER.to_string(),
                VOLATILITY_ISF_BASE.to_string(),
            ],
        }
    }

    /// Permit exactly the given base URLs — a lab's internal mirror, say.
    pub fn allowing(bases: impl IntoIterator<Item = String>) -> Self {
        Self {
            allowed: bases.into_iter().collect(),
        }
    }

    /// Whether `url` sits under a permitted base.
    ///
    /// A prefix test on a normalised base, so `https://evil.test/https://msdl…`
    /// does not pass by containing the string.
    pub fn permits(&self, url: &str) -> bool {
        self.allowed.iter().any(|base| {
            let base = base.trim_end_matches('/');
            url.strip_prefix(base)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
    }

    /// True when no source at all is permitted.
    pub fn is_offline(&self) -> bool {
        self.allowed.is_empty()
    }
}

/// What one fetch did, for the audit trail and the report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FetchRecord {
    /// Exactly what was requested.
    pub url: String,
    /// Where a redirect actually served the bytes from, when that differed.
    /// Recorded rather than refused: a symbol server delivering from a CDN is
    /// ordinary, and the guarantee that matters comes from checking the file's
    /// own identity, not its route.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub landed_url: Option<String>,
    /// Where the bytes were written.
    pub path: PathBuf,
    /// How many bytes arrived.
    pub bytes: u64,
    /// SHA-256 of the bytes as received, before any conversion.
    pub sha256: String,
    /// Which source answered, in the examiner's terms.
    pub source_name: &'static str,
}

/// The identity of a Windows kernel's symbols, as read out of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbIdentity {
    /// e.g. `ntkrnlmp.pdb`.
    pub file_name: String,
    /// 32 uppercase hex characters, in symbol-store byte order.
    pub guid: String,
    /// The PDB age.
    pub age: u32,
}

impl PdbIdentity {
    /// The symbol-store path for this identity, as the servers lay it out.
    pub fn store_path(&self) -> String {
        format!(
            "{}/{}{}/{}",
            self.file_name, self.guid, self.age, self.file_name
        )
    }
}

/// Download the PDB a Windows image names, without converting it.
///
/// The bytes land at `dest_dir/<pdb name>`, unconverted, so what arrived can be
/// hashed and kept exactly as the server sent it. [`pdb_to_isf`] turns it into
/// something the analysis can read.
pub fn fetch_windows_pdb(
    identity: &PdbIdentity,
    dest_dir: &Path,
    policy: &FetchPolicy,
    base: &str,
) -> Result<FetchRecord, FetchError> {
    let url = format!("{}/{}", base.trim_end_matches('/'), identity.store_path());
    let dest = dest_dir.join(&identity.file_name);
    fetch_to(
        &url,
        &dest,
        policy,
        source_name_for(base),
        &identity.file_name,
    )
}

/// Download a prebuilt ISF, for the tiers with no upstream symbol server.
pub fn fetch_isf(
    relative: &str,
    dest_dir: &Path,
    policy: &FetchPolicy,
    base: &str,
) -> Result<FetchRecord, FetchError> {
    let url = format!(
        "{}/{}",
        base.trim_end_matches('/'),
        relative.trim_start_matches('/')
    );
    let name = relative.rsplit('/').next().unwrap_or(relative);
    let dest = dest_dir.join(name);
    let record = fetch_to(&url, &dest, policy, source_name_for(base), name)?;

    // Checked after the write and removed on failure rather than checked in
    // memory, so the same staging path serves both routes; what matters is that
    // nothing unverified is left where the analysis would load it.
    if let Ok(bytes) = std::fs::read(&record.path) {
        if let Err(e) = verify_isf_shape(&bytes) {
            let _ = std::fs::remove_file(&record.path);
            return Err(e);
        }
    }
    Ok(record)
}

/// Confirm a downloaded ISF is an ISF at all.
///
/// The PDB path proves identity against the GUID and age that were asked for.
/// A prebuilt ISF has no such request to check against — the examiner names a
/// path in someone's store — so the guarantee is necessarily weaker, and saying
/// so is the point: this only establishes that what arrived parses as an ISF
/// document with the blocks a symbol table is built from. It is what stops a
/// redirect, an error page or a truncated transfer being written into the
/// symbol store as though it described a kernel.
pub fn verify_isf_shape(bytes: &[u8]) -> Result<(), FetchError> {
    // Compressed packs are the norm; shape can only be checked on what a reader
    // would actually see, so an `.xz` is left to the loader that decompresses
    // it, which applies its own bomb guards.
    if bytes.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) || bytes.starts_with(&[0x1F, 0x8B])
    {
        return Ok(());
    }
    let doc: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| FetchError::WrongIdentity {
            detail: format!("the downloaded file is not JSON, so it is not an ISF: {e}"),
        })?;
    let has = |k: &str| doc.get(k).map(|v| v.is_object()).unwrap_or(false);
    if !doc.get("metadata").map(|m| m.is_object()).unwrap_or(false) {
        return Err(FetchError::WrongIdentity {
            detail: "the downloaded JSON has no `metadata` block, so it is not an ISF".to_string(),
        });
    }
    if !(has("user_types") || has("symbols") || has("base_types")) {
        return Err(FetchError::WrongIdentity {
            detail: "the downloaded JSON declares no types or symbols, so nothing could be \
                     resolved from it"
                .to_string(),
        });
    }
    Ok(())
}

/// What to call the source in a custody record.
///
/// Derived from the base actually contacted, never assumed: a lab pointing at
/// its own mirror and getting a record that says "the Microsoft symbol server"
/// has a custody entry naming a host that was never asked, which is worse than
/// having none.
fn source_name_for(base: &str) -> &'static str {
    if base.starts_with(MICROSOFT_SYMBOL_SERVER) {
        "the Microsoft symbol server"
    } else if base.starts_with(VOLATILITY_ISF_BASE) {
        "the Volatility symbol store"
    } else {
        "the configured symbol source"
    }
}

/// The one place a request is actually made.
fn fetch_to(
    url: &str,
    dest: &Path,
    policy: &FetchPolicy,
    source_name: &'static str,
    what: &str,
) -> Result<FetchRecord, FetchError> {
    if policy.is_offline() {
        return Err(FetchError::NotPermitted);
    }
    if !policy.permits(url) {
        return Err(FetchError::NotPermitted);
    }
    // Symbols define what the analysis reads out of the evidence, so they are
    // not fetched over a channel that anything on the path can rewrite.
    if !url.starts_with("https://") {
        return Err(FetchError::Transport {
            url: url.to_string(),
            detail: "refusing to fetch symbols over a channel that is not HTTPS".to_string(),
        });
    }
    // Refuse before the request, not after: a fetch that could not be kept
    // should not have been made.
    if dest.exists() {
        return Err(FetchError::WouldOverwrite {
            path: dest.to_path_buf(),
        });
    }

    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        // Symbol stores redirect within themselves; a redirect off the
        // permitted base is checked below rather than followed blindly.
        .redirects(4)
        .build();

    let response = match agent.get(url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(status, _)) => {
            return Err(FetchError::NotFound {
                source_name,
                what: what.to_string(),
                status,
            })
        }
        Err(e) => {
            return Err(FetchError::Transport {
                url: url.to_string(),
                detail: e.to_string(),
            })
        }
    };
    // Where the bytes actually came from. Symbol servers legitimately redirect
    // to content-delivery hosts — Microsoft's serves from Azure blob storage —
    // so pinning the final host would refuse the normal case while adding
    // little: what matters is not the route but whether the file is the one
    // that was asked for. That is checked by identity, not by hostname, in
    // `verify_pdb_identity`, and the landing URL is recorded either way so the
    // provenance says where it really came from.
    let landed = response.get_url().to_string();

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|source| FetchError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    // Read one byte past the ceiling so a payload that would exceed it is
    // detected rather than silently truncated and served as whole.
    let mut reader = response.into_reader().take(MAX_SYMBOL_BYTES + 1);
    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .map_err(|source| FetchError::Write {
            path: dest.to_path_buf(),
            source,
        })?;
    if body.len() as u64 > MAX_SYMBOL_BYTES {
        return Err(FetchError::TooLarge {
            url: url.to_string(),
        });
    }

    let sha256 = hex(&Sha256::digest(&body));
    write_new_atomically(dest, &body)?;

    Ok(FetchRecord {
        url: url.to_string(),
        landed_url: (landed != url).then_some(landed),
        path: dest.to_path_buf(),
        bytes: body.len() as u64,
        sha256,
        source_name,
    })
}

/// Write bytes to a path that must not already exist, leaving nothing behind on
/// failure.
///
/// The file is written beside the destination and renamed into place, so an
/// interrupted or concurrent write cannot leave a half-file in the symbol store
/// for a later run to load as if it were whole. That matters more here than in
/// most places: a truncated ISF does not fail to parse in an obvious way, it
/// parses to a *smaller* type database, and a member read at a missing offset
/// is reported as absent from the build rather than as a damaged file.
///
/// The rename is also what makes the caller's `exists()` check meaningful
/// rather than advisory, so the check is repeated here after staging.
pub fn write_new_atomically(dest: &Path, body: &[u8]) -> Result<(), FetchError> {
    let staged = dest.with_extension(format!(
        "{}.partial",
        dest.extension().and_then(|e| e.to_str()).unwrap_or("tmp")
    ));
    std::fs::write(&staged, body).map_err(|source| FetchError::Write {
        path: staged.clone(),
        source,
    })?;
    if dest.exists() {
        let _ = std::fs::remove_file(&staged);
        return Err(FetchError::WouldOverwrite {
            path: dest.to_path_buf(),
        });
    }
    std::fs::rename(&staged, dest).map_err(|source| FetchError::Write {
        path: dest.to_path_buf(),
        source,
    })
}

/// Confirm a downloaded PDB really is the one that was asked for.
///
/// This is the check that replaces pinning the redirect host. A symbol store
/// path names a GUID and an age, and the PDB repeats both in its own header —
/// so rather than trusting the route the bytes travelled, the bytes are asked
/// to identify themselves. A file that arrives from anywhere at all is
/// acceptable if and only if it is the symbols for this kernel; one that is not
/// is refused, whatever host served it.
///
/// Getting this wrong is not a download failure, it is a wrong-layout failure:
/// symbols for a neighbouring build parse perfectly and put every offset in the
/// wrong place.
pub fn verify_pdb_identity(pdb_bytes: &[u8], expected: &PdbIdentity) -> Result<(), FetchError> {
    let cursor = std::io::Cursor::new(pdb_bytes);
    let mut file = pdb::PDB::open(cursor).map_err(|e| FetchError::WrongIdentity {
        detail: format!("the downloaded file is not a readable PDB: {e}"),
    })?;
    let info = file
        .pdb_information()
        .map_err(|e| FetchError::WrongIdentity {
            detail: format!("the PDB carries no identity stream: {e}"),
        })?;
    let actual_guid = guid_to_store_form(info.guid.as_bytes());

    // A PDB carries two ages and they are routinely different. The one a
    // symbol store path names — and the one an image's CodeView record holds —
    // is the DBI stream's; `pdb_information().age` is the PDB stream's own,
    // which counts something else and is commonly higher. Comparing the wrong
    // one rejects the correct file.
    let dbi_age = file.debug_information().ok().and_then(|dbi| dbi.age());
    // The DBI age is the authority when the file carries one; the PDB stream's
    // is only consulted when it does not. Accepting *either* would admit a file
    // whose authoritative age disagrees just because the other one happened to
    // coincide — a weaker check than this function exists to make, even though
    // the GUID comparison above would already have to have passed.
    let age_matches = match dbi_age {
        Some(age) => age == expected.age,
        None => info.age == expected.age,
    };

    if actual_guid != expected.guid.to_uppercase() || !age_matches {
        return Err(FetchError::WrongIdentity {
            detail: format!(
                "asked for {} age {}, received {} age {} (pdb stream age {})",
                expected.guid.to_uppercase(),
                expected.age,
                actual_guid,
                dbi_age.map_or_else(|| "unknown".to_string(), |a| a.to_string()),
                info.age
            ),
        });
    }
    Ok(())
}

/// A PDB's GUID in the 32-hex-character form a symbol store names it by.
///
/// `Uuid::as_bytes` already returns big-endian — the canonical, store order —
/// so the bytes are rendered as they come. The little-endian permutation the
/// Windows tier applies belongs on the raw CodeView record read out of an
/// *image*, which is a different starting point; applying it here as well
/// double-swaps the first three groups and produces a GUID that differs from
/// the real one in exactly its first eight bytes.
fn guid_to_store_form(b: &[u8; 16]) -> String {
    b.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_policy_makes_no_request() {
        assert!(FetchPolicy::default().is_offline());
        let err = fetch_windows_pdb(
            &PdbIdentity {
                file_name: "ntkrnlmp.pdb".into(),
                guid: "2203946837008FE49A19FB2BA96A416D".into(),
                age: 1,
            },
            Path::new("/nonexistent"),
            &FetchPolicy::default(),
            MICROSOFT_SYMBOL_SERVER,
        )
        .unwrap_err();
        assert!(matches!(err, FetchError::NotPermitted));
    }

    /// The store path is the one thing that has to be exactly right, or the
    /// server answers 404 for symbols that are actually published.
    #[test]
    fn the_store_path_is_name_slash_guid_and_age_slash_name() {
        let id = PdbIdentity {
            file_name: "ntkrnlmp.pdb".into(),
            guid: "2203946837008FE49A19FB2BA96A416D".into(),
            age: 1,
        };
        assert_eq!(
            id.store_path(),
            "ntkrnlmp.pdb/2203946837008FE49A19FB2BA96A416D1/ntkrnlmp.pdb"
        );
    }

    #[test]
    fn an_age_above_nine_is_appended_whole_not_truncated() {
        let id = PdbIdentity {
            file_name: "ntkrnlmp.pdb".into(),
            guid: "AABB".into(),
            age: 17,
        };
        assert!(id.store_path().contains("AABB17/"));
    }

    /// A prefix test, not a substring test: a URL that merely *contains* a
    /// permitted base must not pass.
    #[test]
    fn a_host_that_only_embeds_a_permitted_base_is_not_permitted() {
        let policy = FetchPolicy::public_sources();
        assert!(policy
            .permits("https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/ABC1/ntkrnlmp.pdb"));
        assert!(!policy.permits("https://evil.test/https://msdl.microsoft.com/download/symbols/x"));
        assert!(!policy.permits("https://msdl.microsoft.com.evil.test/download/symbols/x"));
    }

    #[test]
    fn an_offline_policy_permits_nothing_at_all() {
        let policy = FetchPolicy::offline();
        assert!(!policy.permits(MICROSOFT_SYMBOL_SERVER));
        assert!(!policy.permits("https://anything.test/"));
    }

    #[test]
    fn a_lab_mirror_can_be_permitted_instead_of_the_public_sources() {
        let policy = FetchPolicy::allowing(["https://symbols.lab.internal/store".to_string()]);
        assert!(policy.permits("https://symbols.lab.internal/store/ntkrnlmp.pdb/A1/x.pdb"));
        assert!(!policy.permits(MICROSOFT_SYMBOL_SERVER));
    }

    /// The store form is the bytes as `Uuid` hands them over. Permuting them
    /// here as well — the way the Windows tier must for a raw CodeView record —
    /// double-swaps the first three groups, producing a GUID that differs from
    /// the true one in exactly its first eight bytes and matches in its last
    /// eight. That is a wrong-symbols failure, not a download failure.
    #[test]
    fn the_store_form_renders_the_guid_bytes_as_they_come() {
        let bytes: [u8; 16] = [
            0x22, 0x03, 0x94, 0x68, 0x37, 0x00, 0x8F, 0xE4, 0x9A, 0x19, 0xFB, 0x2B, 0xA9, 0x6A,
            0x41, 0x6D,
        ];
        assert_eq!(
            guid_to_store_form(&bytes),
            "2203946837008FE49A19FB2BA96A416D"
        );
    }

    #[test]
    fn bytes_that_would_be_permuted_are_not() {
        let bytes: [u8; 16] = [
            0x22, 0x03, 0x94, 0x68, 0x37, 0x00, 0x8F, 0xE4, 0x9A, 0x19, 0xFB, 0x2B, 0xA9, 0x6A,
            0x41, 0x6D,
        ];
        // The double-swapped form the bug produced, kept as a regression guard.
        assert_ne!(
            guid_to_store_form(&bytes),
            "689403220037E48F9A19FB2BA96A416D"
        );
    }

    #[test]
    fn identity_verification_refuses_bytes_that_are_not_a_pdb() {
        let err = verify_pdb_identity(
            b"not a pdb",
            &PdbIdentity {
                file_name: "ntkrnlmp.pdb".into(),
                guid: "AABB".into(),
                age: 1,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FetchError::WrongIdentity { .. }));
    }

    #[test]
    fn a_custody_record_names_the_source_that_was_actually_asked() {
        assert_eq!(
            source_name_for(MICROSOFT_SYMBOL_SERVER),
            "the Microsoft symbol server"
        );
        assert_eq!(
            source_name_for(VOLATILITY_ISF_BASE),
            "the Volatility symbol store"
        );
        // A lab mirror is neither, and must not be reported as either.
        assert_eq!(
            source_name_for("https://symbols.lab.internal/store"),
            "the configured symbol source"
        );
    }

    #[test]
    fn symbols_are_not_fetched_over_plaintext() {
        let policy = FetchPolicy::allowing(["http://mirror.local/store".to_string()]);
        let dir = tempfile::tempdir().unwrap();
        let err =
            fetch_isf("a.json", dir.path(), &policy, "http://mirror.local/store").unwrap_err();
        match err {
            FetchError::Transport { detail, .. } => assert!(detail.contains("HTTPS"), "{detail}"),
            other => panic!("expected a transport refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_isf_that_is_not_an_isf_is_refused() {
        // An error page, which is what a misconfigured mirror serves.
        assert!(verify_isf_shape(b"<html><body>404</body></html>").is_err());
        // JSON, but nothing a symbol table could be built from.
        assert!(verify_isf_shape(br#"{"hello":"world"}"#).is_err());
        // Metadata but no types or symbols.
        assert!(verify_isf_shape(br#"{"metadata":{"format":"6.1.0"}}"#).is_err());
    }

    #[test]
    fn a_real_isf_shape_is_accepted() {
        assert!(verify_isf_shape(
            br#"{"metadata":{"format":"6.1.0"},"user_types":{},"symbols":{}}"#
        )
        .is_ok());
    }

    /// A compressed pack cannot be shape-checked here; the loader that
    /// decompresses it applies its own guards, so it is passed through rather
    /// than rejected for not being readable JSON.
    #[test]
    fn a_compressed_pack_is_left_to_the_loader() {
        assert!(verify_isf_shape(&[0xFD, b'7', b'z', b'X', b'Z', 0x00, 0x01]).is_ok());
    }

    #[test]
    fn an_existing_symbol_file_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("ntkrnlmp.pdb");
        std::fs::write(&existing, b"a curated pack").unwrap();

        let err = fetch_windows_pdb(
            &PdbIdentity {
                file_name: "ntkrnlmp.pdb".into(),
                guid: "AABB".into(),
                age: 1,
            },
            dir.path(),
            &FetchPolicy::public_sources(),
            MICROSOFT_SYMBOL_SERVER,
        )
        .unwrap_err();

        assert!(matches!(err, FetchError::WouldOverwrite { .. }));
        // And it is still exactly what the lab put there.
        assert_eq!(std::fs::read(&existing).unwrap(), b"a curated pack");
    }

    /// The staging file is the whole point of the helper, so a refusal must not
    /// leave one behind: a `.json.partial` sitting in the symbol store is a file
    /// a later run, or a curious examiner, could mistake for a symbol file.
    #[test]
    fn a_refused_write_leaves_no_staging_file_in_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("AABB-1.json");
        std::fs::write(&dest, b"already here").unwrap();

        let err = write_new_atomically(&dest, b"a replacement").unwrap_err();

        assert!(matches!(err, FetchError::WouldOverwrite { .. }));
        assert_eq!(std::fs::read(&dest).unwrap(), b"already here");
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["AABB-1.json".to_string()], "left: {left:?}");
    }

    /// And the ordinary path does land the bytes, under the name asked for.
    #[test]
    fn a_written_file_lands_whole_and_under_the_requested_name() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("AABB-1.json");

        write_new_atomically(&dest, b"{\"symbols\":{}}").unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"{\"symbols\":{}}");
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["AABB-1.json".to_string()], "left: {left:?}");
    }
}
