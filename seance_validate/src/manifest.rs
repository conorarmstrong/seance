//! The corpus provenance manifest (`ROADMAP` §5.2).
//!
//! # Why this exists at all
//!
//! A CFTT run is only worth publishing if somebody else can re-run it on the
//! same bytes. This records, per file: where it came from, how long it is, our
//! SHA-256, the publisher's SHA-256, **and whether the publisher published one
//! at all**.
//!
//! That last field is the point of the module. Of the three CFTT data sets
//! §5.2 needs, only the string-search set ships a hash list; the deleted-file
//! recovery and carving sets publish none. A manifest that simply omitted the
//! publisher's hash where there was none would read, to anybody scanning it, as
//! a file that had been verified. So the absence is a value — `NotPublished` —
//! and a file in that state can never be `Verified`.
//!
//! # And why it is committed
//!
//! This item's own history. A DFR sweep was run on 2026-09-11 and is
//! **unreproducible**: its grader was never in the repository and its images
//! were deleted after grading. A recorded run whose method is gone is an
//! anecdote.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// What is known about a file's agreement with its publisher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum Provenance {
    /// The publisher published a hash and ours equals it.
    Verified { publisher_sha256: String },
    /// The publisher published a hash and ours does **not** equal it. The run
    /// must stop: the bytes are not the bytes the assertions were written for.
    Mismatch {
        publisher_sha256: String,
        ours: String,
    },
    /// **The publisher published no hash list.** Our digest is a
    /// first-acquisition record and nothing more: it says these bytes are what
    /// we fetched, not that they are what the publisher shipped.
    NotPublished {
        /// Where the absence was established, so it can be re-checked.
        checked: String,
    },
}

impl Provenance {
    /// Whether the file's bytes have been checked against the publisher's own
    /// statement of them.
    ///
    /// `false` for `NotPublished`, which is the whole reason this type is not
    /// an `Option<String>`.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// The sentence a reader needs, rather than a state name.
    pub fn describe(&self) -> String {
        match self {
            Self::Verified { .. } => {
                "verified: our SHA-256 equals the publisher's own published hash".to_string()
            }
            Self::Mismatch {
                publisher_sha256,
                ours,
            } => format!(
                "MISMATCH: the publisher publishes {publisher_sha256} and these bytes hash to \
                 {ours}. They are not the bytes the published assertions were written for, and a \
                 run against them would grade something else."
            ),
            Self::NotPublished { checked } => format!(
                "not verifiable: the publisher publishes no hash list for this data set \
                 ({checked}). Our SHA-256 below is a record of what we fetched -- a \
                 first-acquisition hash -- and is NOT a check against the publisher."
            ),
        }
    }
}

/// One file in a corpus data set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Path relative to the data set's directory.
    pub path: String,
    /// Where it was fetched from.
    pub url: String,
    pub bytes: u64,
    /// Our SHA-256 of the bytes on disk.
    pub sha256: String,
    pub provenance: Provenance,
}

/// One CFTT data set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataSet {
    /// The corpus directory name, e.g. `cftt_string_search`.
    pub name: String,
    /// The CFTT family this set serves.
    pub methodology: String,
    /// The publisher's index page, so a reader can go and look.
    pub source_page: String,
    /// The publisher's hash list, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher_hash_list: Option<String>,
    pub files: Vec<ManifestEntry>,
}

impl DataSet {
    /// Files whose bytes agree with the publisher's own statement of them.
    pub fn verified(&self) -> usize {
        self.files
            .iter()
            .filter(|f| f.provenance.is_verified())
            .count()
    }

    /// Files the publisher published no hash for. **Not** a count of problems:
    /// a count of what cannot be checked.
    pub fn unverifiable(&self) -> usize {
        self.files
            .iter()
            .filter(|f| matches!(f.provenance, Provenance::NotPublished { .. }))
            .count()
    }

    /// Files whose bytes disagree with the publisher. Any of these stops a run.
    pub fn mismatched(&self) -> usize {
        self.files
            .iter()
            .filter(|f| matches!(f.provenance, Provenance::Mismatch { .. }))
            .count()
    }

    /// Whether a run against this set may proceed.
    ///
    /// A mismatch is fatal: the bytes are not the bytes the published
    /// assertions describe. An unverifiable file is **not** fatal — most of
    /// CFTT's data is unverifiable, and refusing it would refuse the work —
    /// but it must be stated, which is what `describe_readiness` is for.
    pub fn may_run(&self) -> bool {
        self.mismatched() == 0 && !self.files.is_empty()
    }

    /// What a reader must be told before a result from this set is quoted.
    pub fn describe_readiness(&self) -> String {
        if self.files.is_empty() {
            return format!(
                "The `{}` data set holds no files. Nothing was fetched, so nothing about this \
                 methodology is established either way.",
                self.name
            );
        }
        if self.mismatched() > 0 {
            return format!(
                "{} of {} files in `{}` do NOT match the publisher's own published hash. No run \
                 may be quoted from this set: the bytes are not the bytes the published \
                 assertions were written for.",
                self.mismatched(),
                self.files.len(),
                self.name
            );
        }
        let total = self.files.len();
        match (self.verified(), self.unverifiable()) {
            (v, 0) => format!(
                "All {v} of {total} files in `{}` are verified against the publisher's own \
                 published hash list.",
                self.name
            ),
            (0, u) => format!(
                "None of the {u} files in `{}` can be verified against the publisher: this data \
                 set publishes no hash list. Their SHA-256 values in this manifest are \
                 first-acquisition records of what we fetched, and a second party re-running \
                 this work should compare against them rather than against the publisher.",
                self.name
            ),
            (v, u) => format!(
                "{v} of {total} files in `{}` are verified against the publisher's published \
                 hash list; the other {u} cannot be, because no published hash exists for them. \
                 Their digests here are first-acquisition records only.",
                self.name
            ),
        }
    }
}

/// The whole manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusManifest {
    /// RFC 3339, when the manifest was written.
    pub generated_at: String,
    pub sets: Vec<DataSet>,
}

impl CorpusManifest {
    /// Render the manifest as the paragraph a validation document needs.
    pub fn render_markdown(&self) -> String {
        let mut md = String::from("## CFTT corpus provenance\n\n");
        md.push_str(&format!("Generated {}.\n\n", self.generated_at));
        for set in &self.sets {
            md.push_str(&format!(
                "### `{}` — {}\n\n{}\n\nSource: {}\n\n",
                set.name,
                set.methodology,
                set.describe_readiness(),
                set.source_page
            ));
            md.push_str("| File | Bytes | Our SHA-256 | Publisher's |\n");
            md.push_str("|------|-------|-------------|-------------|\n");
            for f in &set.files {
                let publisher = match &f.provenance {
                    Provenance::Verified { publisher_sha256 } => publisher_sha256.clone(),
                    Provenance::Mismatch {
                        publisher_sha256, ..
                    } => {
                        format!("**{publisher_sha256} — MISMATCH**")
                    }
                    // Said in words, not left blank. A blank here is exactly
                    // what would read as "verified".
                    Provenance::NotPublished { .. } => "*none published*".to_string(),
                };
                md.push_str(&format!(
                    "| `{}` | {} | `{}` | {} |\n",
                    f.path, f.bytes, f.sha256, publisher
                ));
            }
            md.push('\n');
        }
        md
    }
}

/// SHA-256 of a file, streamed so a 2 GB image never loads at once.
pub fn sha256_of(path: &Path) -> std::io::Result<(String, u64)> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        hasher.update(&buf[..n]);
    }
    let mut out = String::with_capacity(64);
    for b in hasher.finalize() {
        out.push_str(&format!("{b:02x}"));
    }
    Ok((out, total))
}

/// Parse a publisher hash list, in either of the two forms CFTT ships.
///
/// `<hex>  <path>` is what its SHA-1 and SHA-256 lists use — with **two**
/// spaces — and `ALGO (<path>) = <hex>` is the BSD form its MD5 list uses. Both
/// are real, in the same directory, in the string-search set: a parser that
/// knew only the first read **zero** entries from `hash-md5.txt` and would have
/// reported "the publisher published no hash" about a list sitting next to the
/// files. That is the shape of failure this whole module exists against.
///
/// Its paths do not always match the names inside the archive — measured: the
/// list names `Expected Results by ID - 07-25 Data Set.pdf` and the archive
/// holds `Expected Results by ID v1.1 9-27-19.pdf` — so entries are keyed on
/// the base name and a name the archive lacks is reported as absent rather than
/// quietly dropped.
///
/// A line this parser does not understand is skipped and **counted**, never
/// guessed at: a hash bound to the wrong file would report a verification that
/// did not happen.
pub fn parse_hash_list(text: &str) -> (std::collections::BTreeMap<String, String>, usize) {
    let mut out = std::collections::BTreeMap::new();
    let mut unparsed = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // The BSD form: `MD5 (some/path) = <hex>`.
        if let Some((head, hex)) = line.rsplit_once(" = ") {
            if let Some(open) = head.find(" (") {
                if let Some(path) = head[open + 2..].strip_suffix(')') {
                    let hex = hex.trim().to_ascii_lowercase();
                    let ok = !hex.is_empty()
                        && hex.len() % 2 == 0
                        && hex.bytes().all(|b| b.is_ascii_hexdigit());
                    if ok && !path.is_empty() {
                        let base = path.rsplit(['/', '\\']).next().unwrap_or(path).to_string();
                        out.insert(base, hex);
                    } else {
                        unparsed += 1;
                    }
                    continue;
                }
            }
        }
        let Some((hex, path)) = line.split_once(char::is_whitespace) else {
            unparsed += 1;
            continue;
        };
        let hex = hex.trim().to_ascii_lowercase();
        let path = path.trim().trim_start_matches('*');
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) || path.is_empty() {
            unparsed += 1;
            continue;
        }
        // Keyed on the base name: the hash list's paths and the archive's do
        // not agree for every file in the real set.
        let base = path.rsplit(['/', '\\']).next().unwrap_or(path).to_string();
        out.insert(base, hex);
    }
    (out, unparsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, prov: Provenance) -> ManifestEntry {
        ManifestEntry {
            path: path.to_string(),
            url: format!("https://example.invalid/{path}"),
            bytes: 1024,
            sha256: "a".repeat(64),
            provenance: prov,
        }
    }

    fn set(name: &str, files: Vec<ManifestEntry>) -> DataSet {
        DataSet {
            name: name.to_string(),
            methodology: "Forensic String Search".to_string(),
            source_page: "https://example.invalid/".to_string(),
            publisher_hash_list: None,
            files,
        }
    }

    /// **The whole point of the type.** A file the publisher never hashed is
    /// not verified, and cannot be made to look verified.
    #[test]
    fn a_file_with_no_published_hash_is_never_verified() {
        let p = Provenance::NotPublished {
            checked: "the index page publishes no hash list".to_string(),
        };
        assert!(!p.is_verified());
        let said = p.describe();
        assert!(
            said.contains("not verifiable")
                && said.contains("is NOT a check against the publisher"),
            "the absence is said in words, not implied by a blank: {said}"
        );
        // And in the rendered table it is words, not an empty cell.
        let md = CorpusManifest {
            generated_at: "2026-09-15T00:00:00Z".to_string(),
            sets: vec![set("cftt_dfr", vec![entry("dfr-01-ntfs.dd", p)])],
        }
        .render_markdown();
        assert!(md.contains("*none published*"), "{md}");
        assert!(
            !md.contains("|  |"),
            "an empty cell is what reads as verified: {md}"
        );
    }

    /// A set nobody published hashes for may still be run, and the reader is
    /// told exactly what its digests do and do not establish.
    #[test]
    fn an_unverifiable_set_may_run_and_says_what_its_digests_mean() {
        let s = set(
            "cftt_dfr",
            vec![
                entry(
                    "a.dd",
                    Provenance::NotPublished {
                        checked: "no hash list".to_string(),
                    },
                ),
                entry(
                    "b.dd",
                    Provenance::NotPublished {
                        checked: "no hash list".to_string(),
                    },
                ),
            ],
        );
        assert!(s.may_run(), "most of CFTT's data is unverifiable");
        assert_eq!(s.verified(), 0);
        assert_eq!(s.unverifiable(), 2);
        let said = s.describe_readiness();
        assert!(
            said.contains("publishes no hash list") && said.contains("first-acquisition records"),
            "got {said}"
        );
    }

    /// **A mismatch stops the run.** The bytes are not the bytes the published
    /// assertions were written for, so a result from them grades something
    /// else.
    #[test]
    fn a_mismatch_stops_the_run_and_says_why() {
        let s = set(
            "cftt_string_search",
            vec![
                entry(
                    "ss-win.dd",
                    Provenance::Mismatch {
                        publisher_sha256: "b".repeat(64),
                        ours: "a".repeat(64),
                    },
                ),
                entry(
                    "win_string_doc.txt",
                    Provenance::Verified {
                        publisher_sha256: "a".repeat(64),
                    },
                ),
            ],
        );
        assert!(!s.may_run());
        assert_eq!(s.mismatched(), 1);
        let said = s.describe_readiness();
        assert!(
            said.contains("No run may be quoted") && said.contains("1 of 2"),
            "got {said}"
        );
    }

    /// An empty set is not a verified set. Nothing was fetched, so nothing is
    /// established either way.
    #[test]
    fn an_empty_set_may_not_run_and_claims_nothing() {
        let s = set("cftt_mobile", vec![]);
        assert!(!s.may_run());
        assert!(
            s.describe_readiness().contains("holds no files"),
            "got {}",
            s.describe_readiness()
        );
    }

    /// A set with some published hashes and some not says both halves, because
    /// "3 of 6 verified" is the honest headline and "verified" is not.
    #[test]
    fn a_partly_verifiable_set_states_both_halves() {
        let s = set(
            "cftt_string_search",
            vec![
                entry(
                    "a",
                    Provenance::Verified {
                        publisher_sha256: "a".repeat(64),
                    },
                ),
                entry(
                    "b",
                    Provenance::NotPublished {
                        checked: "absent from hash-sha256.txt".to_string(),
                    },
                ),
            ],
        );
        let said = s.describe_readiness();
        assert!(said.contains("1 of 2"), "got {said}");
        assert!(
            said.contains("cannot be") && said.contains("first-acquisition"),
            "got {said}"
        );
    }

    // --- the publisher's hash list -----------------------------------------

    /// The real format: `<hex>` then **two** spaces then a path.
    #[test]
    fn a_publisher_hash_list_parses_on_its_real_shape() {
        let text = "1574185b8dedc343ceb7dd306099a7bd41ceb77730b52c8d97181aeb792b6eb9  \
                    copy-to-test-computer/ss-win-07-25-18.dd\n\
                    42bc298d973710c9906568d2d460f980c4523d0308a73f85984fa29d58a320ee  \
                    copy-to-test-computer/ss-unix-07-25-18.dd\n";
        let (map, unparsed) = parse_hash_list(text);
        assert_eq!(unparsed, 0);
        assert_eq!(
            map.get("ss-win-07-25-18.dd").map(String::as_str),
            Some("1574185b8dedc343ceb7dd306099a7bd41ceb77730b52c8d97181aeb792b6eb9"),
            "keyed on the base name, because the hash list's paths and the archive's do not agree"
        );
        assert_eq!(map.len(), 2);
    }

    /// **A line this parser does not understand is counted, never guessed.** A
    /// hash bound to the wrong file would report a verification that did not
    /// happen.
    #[test]
    fn an_unparseable_hash_line_is_counted_and_not_guessed() {
        let text = "# a comment\n\
                    \n\
                    deadbeef  too-short-a-hash.dd\n\
                    not-hex-at-all-but-sixty-four-characters-long-xxxxxxxxxxxxxxxxxxx  x.dd\n\
                    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
                    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  good.dd\n";
        let (map, unparsed) = parse_hash_list(text);
        assert_eq!(map.len(), 1, "only the well-formed line: {map:?}");
        assert!(map.contains_key("good.dd"));
        assert_eq!(unparsed, 3, "and the rest are counted");
    }

    /// A `*`-prefixed path, which some hash tools write for a binary file.
    #[test]
    fn a_binary_marked_path_is_read_without_its_marker() {
        let (map, unparsed) = parse_hash_list(&format!("{}  *image.dd\n", "c".repeat(64)));
        assert_eq!(unparsed, 0);
        assert!(map.contains_key("image.dd"), "{map:?}");
    }

    /// Case is not significant in a hex digest, and a manifest keyed on the
    /// literal case would fail to verify a file the publisher hashed in
    /// upper case.
    #[test]
    fn an_upper_case_digest_is_read_as_the_same_digest() {
        let (map, _) = parse_hash_list(&format!("{}  x.dd\n", "AB".repeat(32)));
        assert_eq!(
            map.get("x.dd").map(String::as_str),
            Some(&"ab".repeat(32)[..])
        );
    }

    // --- hashing a real file ------------------------------------------------

    #[test]
    fn the_digest_and_the_length_are_both_measured_from_the_bytes() {
        let dir = std::env::temp_dir().join(format!("seance-manifest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("x.bin");
        std::fs::write(&path, b"abc").expect("write");
        let (hex, len) = sha256_of(&path).expect("hash");
        assert_eq!(len, 3);
        assert_eq!(
            hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "the published SHA-256 of \"abc\""
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The manifest round-trips, so a committed one can be read back and
    /// re-checked rather than re-derived.
    #[test]
    fn the_manifest_round_trips_through_json() {
        let m = CorpusManifest {
            generated_at: "2026-09-15T00:00:00Z".to_string(),
            sets: vec![set(
                "cftt_string_search",
                vec![entry(
                    "ss-win.dd",
                    Provenance::Verified {
                        publisher_sha256: "a".repeat(64),
                    },
                )],
            )],
        };
        let json = serde_json::to_string_pretty(&m).expect("serialises");
        let back: CorpusManifest = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, m);
        // And the state is on the wire as a name, so a reader of the JSON sees
        // which of the three it is without decoding a shape.
        assert!(json.contains("\"state\": \"verified\""), "{json}");
    }
}

#[cfg(test)]
mod bsd_hash_list_tests {
    use super::*;

    /// **A real list this parser would have read as empty.**
    ///
    /// The CFTT string-search set ships three hash lists in one directory, and
    /// `hash-md5.txt` uses the BSD form while the other two use `<hex>  <path>`.
    /// Measured, verbatim, from the fetched set:
    ///
    /// ```text
    /// MD5 (Expected Results by ID - 07-25 Data Set.docx) = a4439ee437eae242a8b4ee8886373705
    /// MD5 (copy-to-test-computer/ss-win-07-25-18.dd) = dcb0196ce0ee873f6a39dc86b7678ced
    /// ```
    ///
    /// A parser that knew only the other form returned nothing from it — and
    /// "nothing" would have been recorded as "the publisher published no hash",
    /// about a list sitting next to the files.
    #[test]
    fn the_bsd_form_a_real_publisher_list_uses_is_read() {
        let text = "MD5 (Expected Results by ID - 07-25 Data Set.docx) = \
                    a4439ee437eae242a8b4ee8886373705\n\
                    MD5 (copy-to-test-computer/ss-win-07-25-18.dd) = \
                    dcb0196ce0ee873f6a39dc86b7678ced\n";
        let (map, unparsed) = parse_hash_list(text);
        assert_eq!(unparsed, 0);
        assert_eq!(map.len(), 2, "{map:?}");
        assert_eq!(
            map.get("ss-win-07-25-18.dd").map(String::as_str),
            Some("dcb0196ce0ee873f6a39dc86b7678ced"),
            "the image's real MD5, from the publisher's own list"
        );
        assert!(map.contains_key("Expected Results by ID - 07-25 Data Set.docx"));
    }

    /// Both forms in one file, which is what a concatenated list looks like.
    #[test]
    fn the_two_forms_can_appear_in_one_list() {
        let text = format!(
            "SHA256 (a.dd) = {}\n{}  b.dd\n",
            "a".repeat(64),
            "b".repeat(64)
        );
        let (map, unparsed) = parse_hash_list(&text);
        assert_eq!(unparsed, 0);
        assert_eq!(map.len(), 2, "{map:?}");
    }

    /// A BSD line whose digest is not hex is counted, not guessed.
    #[test]
    fn a_malformed_bsd_line_is_counted() {
        let (map, unparsed) = parse_hash_list("MD5 (x.dd) = not-a-digest\n");
        assert!(map.is_empty());
        assert_eq!(unparsed, 1);
    }

    /// A path containing " = " must not be split on it: the digest is the LAST
    /// field, which is why the split is from the right.
    #[test]
    fn a_path_containing_the_separator_is_not_mis_split() {
        let (map, unparsed) =
            parse_hash_list(&format!("MD5 (odd = name.dd) = {}\n", "c".repeat(32)));
        assert_eq!(unparsed, 0);
        assert_eq!(
            map.get("odd = name.dd").map(String::as_str),
            Some(&"c".repeat(32)[..]),
            "{map:?}"
        );
    }
}
