//! Choosing the symbol pack that describes *this* kernel, and refusing every
//! other one.
//!
//! # Why this is the most dangerous step
//!
//! A wrong symbol table does not crash and does not look wrong. It produces a
//! full process list with plausible PIDs, plausible names and plausible start
//! times, all of it garbage, because `proc.p_pid` was read at the offset a
//! *different* Darwin build uses. Nothing downstream can detect it: the bytes
//! really were at that address and they really did parse.
//!
//! This is not hypothetical on macOS. Across the 129 Kernel Debug Kit packs in
//! `reference/volatility3/volatility3/symbols`, `proc.p_pid` sits at offset 16
//! on Darwin 12 through 17 and at offset 96 on Darwin 18 — two builds a year
//! apart, and one number apiece. `p_start` moves from 1048 to 1064 to 960 to
//! 928 across four packs. So selection is on the kernel banner and nothing else:
//! not the file name, not the marketing version, not the nearest build.
//!
//! # The banner is the identity
//!
//! `IsfOs::Mac` packs declare their identity as the `version` symbol's constant
//! data — the `Darwin Kernel Version …` string, including the build timestamp
//! and the xnu source tag. Two packs with the same banner describe the same
//! kernel binary; two with different banners describe different kernels however
//! close their version numbers.
//!
//! # What this store actually holds
//!
//! Surveyed from the 129 packs present when this crate was written:
//!
//! | | packs | usable here |
//! |---|---|---|
//! | 64-bit (Darwin 12–19, OS X 10.8 – macOS 10.15.4) | 117 | yes |
//! | 32-bit (Darwin 10–11, Mac OS X 10.6 – 10.7) | 12 | **no** |
//!
//! The twelve 32-bit packs declare no `version` constant data at all, so they
//! carry no identity to match an image against, and they declare no `BootPML4`,
//! which is the symbol discovery bootstraps the address space from. They are
//! counted and reported ([`MacIsfIndex::skipped_no_banner`]) rather than
//! silently dropped, so an examiner with a 10.6 image is told why nothing
//! matched instead of being told nothing matched.
//!
//! **Unvalidated.** See [`crate::unvalidated`].

use std::collections::BTreeMap;
use std::path::PathBuf;

pub use seance_memory::isf_files::{
    collect_isf_files, is_isf_file_name, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILES, ISF_SUFFIXES,
};
use seance_symbols::isf::MAC_BANNER_SYMBOL;
use seance_symbols::{identify_path, IdentifyOptions, IsfOs};

/// Files the search will open and identify. Identifying an ISF streams and
/// hashes the whole file, so an exhaustive pass over a large store is expensive
/// and is bounded.
pub const DEFAULT_MAX_IDENTIFIED: usize = 4_096;

/// One macOS symbol pack and the kernel it declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacIsfEntry {
    /// Where the pack is.
    pub path: PathBuf,
    /// The banner the pack declares, normalised.
    pub banner: String,
}

/// Every macOS pack found under the search directories, indexed by banner.
#[derive(Debug, Clone, Default)]
pub struct MacIsfIndex {
    /// Packs by banner. A banner declared by two files keeps the first by path
    /// order, and the duplicate is counted in [`MacIsfIndex::duplicate_banners`]
    /// — two files claiming one kernel is worth reporting, and picking between
    /// them on content is not something a name can decide.
    by_banner: BTreeMap<String, MacIsfEntry>,
    /// Candidate files enumerated.
    pub files_seen: usize,
    /// Files opened and identified.
    pub files_identified: usize,
    /// Files that identified as macOS packs but declared no banner, so they
    /// carry no identity an image can be matched against. The twelve 32-bit
    /// Mac OS X 10.6/10.7 packs in this repository are all of this kind.
    pub skipped_no_banner: usize,
    /// Files that identified as some other operating system's symbols.
    pub skipped_other_os: usize,
    /// Banners declared by more than one file.
    pub duplicate_banners: usize,
    /// Whether a cap stopped the search.
    pub truncated: bool,
}

impl MacIsfIndex {
    /// The pack declaring exactly this banner, if the store holds one.
    ///
    /// Exact match only. There is no nearest-build fallback and there will not
    /// be one: the closest pack to a kernel is a different kernel.
    pub fn lookup(&self, banner: &str) -> Option<&MacIsfEntry> {
        self.by_banner.get(banner)
    }

    /// Number of packs indexed.
    pub fn len(&self) -> usize {
        self.by_banner.len()
    }

    /// Whether the index holds no pack at all.
    pub fn is_empty(&self) -> bool {
        self.by_banner.is_empty()
    }

    /// Every banner the store can analyse, for a failure record to show an
    /// examiner what *is* available.
    pub fn banners(&self) -> Vec<&str> {
        self.by_banner.keys().map(String::as_str).collect()
    }

    /// Serializable form for the discovery record.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "packs_indexed": self.len(),
            "files_seen": self.files_seen,
            "files_identified": self.files_identified,
            "skipped_no_banner": self.skipped_no_banner,
            "skipped_other_os": self.skipped_other_os,
            "duplicate_banners": self.duplicate_banners,
            "truncated": self.truncated,
        })
    }
}

/// Stage-A options for one candidate file.
///
/// Only the macOS banner symbol is captured. Asking for `linux_banner` as well
/// costs a buffer per file and nothing here could use it.
///
/// Built in one place so there is a single way this crate asks "what is this
/// file?". A second construction that quietly differed — a larger symbol
/// budget, a different decompression limit — would answer differently for the
/// same file, and which answer a case got would depend on which code path
/// reached it first.
fn identify_options() -> IdentifyOptions {
    IdentifyOptions {
        banner_symbols: vec![MAC_BANNER_SYMBOL.to_string()],
        ..IdentifyOptions::default()
    }
}

/// Build the banner index over `dirs`.
///
/// Every candidate file is opened, because unlike a Windows symbol store there
/// is no name convention that encodes a macOS kernel's identity — the packs in
/// this repository are named for the Kernel Debug Kit disk image they came from,
/// which names a *marketing* version and not the banner. So the file name is
/// never evidence here, not even as a hint.
pub fn build_index(
    dirs: &[PathBuf],
    max_files: usize,
    max_depth: usize,
    max_identified: usize,
) -> MacIsfIndex {
    let (files, truncated) = collect_isf_files(dirs, max_files, max_depth);
    let mut index = MacIsfIndex {
        files_seen: files.len(),
        truncated,
        ..MacIsfIndex::default()
    };

    for path in files {
        if index.files_identified >= max_identified {
            index.truncated = true;
            break;
        }
        index.files_identified += 1;

        let Ok(identity) = identify_path(&path, &identify_options()) else {
            continue;
        };
        if identity.os != IsfOs::Mac {
            index.skipped_other_os += 1;
            continue;
        }
        let Some(banner) = identity.identifier else {
            // A macOS pack with no banner. Real, and there are twelve of them
            // here: the 32-bit Mac OS X 10.6 and 10.7 kits. Counted so the
            // failure record can say "twelve packs were present and none of
            // them could be matched to any image" rather than implying the
            // store was empty.
            index.skipped_no_banner += 1;
            continue;
        };
        let entry = MacIsfEntry {
            path,
            banner: banner.clone(),
        };
        if index.by_banner.insert(banner, entry).is_some() {
            // Two files claiming one kernel. Counted rather than resolved: a
            // file name cannot decide which of them describes the image, and
            // both compile to the same declared identity anyway.
            index.duplicate_banners += 1;
        }
    }

    index
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A throwaway directory that removes itself.
    pub(crate) struct TempDir {
        pub path: PathBuf,
    }

    impl TempDir {
        pub(crate) fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("seance-macos-isf-{label}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("a writable temporary directory");
            Self { path }
        }

        pub(crate) fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let full = self.path.join(relative);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).expect("a writable temporary directory");
            }
            std::fs::write(&full, contents).expect("a writable temporary file");
            full
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Base64 of `banner` followed by the trailing NUL dwarf2json emits.
    fn banner_constant(banner: &str) -> String {
        let mut bytes = banner.as_bytes().to_vec();
        bytes.push(0);
        base64_encode(&bytes)
    }

    /// Minimal standard base64. The symbols crate has a decoder and no public
    /// encoder, and a test fixture needs one.
    fn base64_encode(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[(triple >> 18) as usize & 63] as char);
            out.push(ALPHABET[(triple >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(triple >> 6) as usize & 63] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[triple as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    /// A minimal but genuinely valid macOS ISF declaring one banner, and enough
    /// of a type database that it compiles.
    pub(crate) fn mac_isf(banner: &str) -> String {
        let constant = banner_constant(banner);
        format!(
            r#"{{
  "metadata": {{
    "format": "6.2.0",
    "producer": {{"name": "seance-test", "version": "1.0.0"}},
    "mac": {{"symbols": [], "types": []}}
  }},
  "base_types": {{
    "pointer": {{"size": 8, "signed": false, "kind": "int", "endian": "little"}},
    "int": {{"size": 4, "signed": true, "kind": "int", "endian": "little"}},
    "unsigned int": {{"size": 4, "signed": false, "kind": "int", "endian": "little"}},
    "char": {{"size": 1, "signed": true, "kind": "char", "endian": "little"}},
    "long long unsigned int": {{"size": 8, "signed": false, "kind": "int", "endian": "little"}}
  }},
  "user_types": {{
    "proclist": {{"size": 8, "kind": "struct", "fields": {{
      "lh_first": {{"offset": 0, "type": {{"kind": "pointer", "subtype": {{"kind": "struct", "name": "proc"}}}}}}
    }}}},
    "proc": {{"size": 1136, "kind": "struct", "fields": {{
      "p_list": {{"offset": 0, "type": {{"kind": "struct", "name": "proc_link"}}}},
      "p_pid": {{"offset": 96, "type": {{"kind": "base", "name": "int"}}}},
      "p_ppid": {{"offset": 32, "type": {{"kind": "base", "name": "int"}}}}
    }}}},
    "proc_link": {{"size": 16, "kind": "struct", "fields": {{
      "le_next": {{"offset": 0, "type": {{"kind": "pointer", "subtype": {{"kind": "struct", "name": "proc"}}}}}},
      "le_prev": {{"offset": 8, "type": {{"kind": "pointer", "subtype": {{"kind": "struct", "name": "proc"}}}}}}
    }}}}
  }},
  "enums": {{}},
  "symbols": {{
    "version": {{"address": 18446743523965382256, "type": {{"kind": "base", "name": "char"}}, "constant_data": "{constant}"}},
    "allproc": {{"address": 18446743523968531096, "type": {{"kind": "struct", "name": "proclist"}}}}
  }}
}}"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    const BANNER_A: &str = "Darwin Kernel Version 18.7.0: Thu Jun 20 18:42:21 PDT 2019; \
                            root:xnu-4903.270.47~4/RELEASE_X86_64";
    const BANNER_B: &str = "Darwin Kernel Version 19.4.0: Wed Mar  4 22:28:40 PST 2020; \
                            root:xnu-6153.101.6~15/RELEASE_X86_64";

    #[test]
    fn an_isf_is_recognised_by_the_suffixes_this_crate_can_read() {
        assert!(is_isf_file_name("kernel.json"));
        assert!(is_isf_file_name("Kernel_Debug_Kit_10.14.6.dmg.json.xz"));
        assert!(is_isf_file_name("PACK.JSON.GZ"));
        assert!(!is_isf_file_name("kernel.dSYM"));
        assert!(!is_isf_file_name("notes.txt"));
        assert!(!is_isf_file_name("pack.json.bz2"));
    }

    #[test]
    fn a_pack_is_indexed_under_the_banner_it_declares() {
        let dir = TempDir::new("index");
        dir.write("kits/one.json", &mac_isf(BANNER_A));
        dir.write("kits/two.json", &mac_isf(BANNER_B));

        let index = build_index(
            std::slice::from_ref(&dir.path),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_IDENTIFIED,
        );
        assert_eq!(index.len(), 2, "{:?}", index);
        assert_eq!(index.files_identified, 2);
        assert!(index.lookup(BANNER_A).is_some());
        assert!(index.lookup(BANNER_B).is_some());
        assert_eq!(index.lookup(BANNER_A).expect("indexed").banner, BANNER_A);
    }

    #[test]
    fn a_banner_one_character_different_does_not_match() {
        // The nearest pack is a different kernel. There is no fallback and
        // there must not be one: a build timestamp differing by an hour is a
        // different kernel binary with different structure offsets.
        let dir = TempDir::new("nearest");
        dir.write("one.json", &mac_isf(BANNER_A));
        let index = build_index(
            std::slice::from_ref(&dir.path),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_IDENTIFIED,
        );
        let almost = BANNER_A.replace("18:42:21", "18:42:22");
        assert!(index.lookup(&almost).is_none());
        assert!(index.lookup(BANNER_A).is_some());
    }

    #[test]
    fn a_search_that_hits_its_budget_says_so_rather_than_reading_as_exhaustive() {
        let dir = TempDir::new("budget");
        for index in 0..4 {
            dir.write(&format!("pack{index}.json"), &mac_isf(BANNER_A));
        }
        let index = build_index(
            std::slice::from_ref(&dir.path),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            2,
        );
        assert!(index.truncated);
        assert_eq!(index.files_identified, 2);
    }

    #[test]
    fn files_that_are_not_symbol_files_are_never_opened() {
        let dir = TempDir::new("noise");
        dir.write("kernel.dSYM", "not an ISF at all");
        dir.write("notes.txt", "nor is this");
        let index = build_index(
            std::slice::from_ref(&dir.path),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_IDENTIFIED,
        );
        assert_eq!(index.files_seen, 0);
        assert_eq!(index.files_identified, 0);
        assert!(index.is_empty());
    }

    #[test]
    fn a_directory_that_cannot_be_read_does_not_fail_the_whole_search() {
        let dir = TempDir::new("partial");
        dir.write("one.json", &mac_isf(BANNER_A));
        let missing = dir.path.join("not-a-real-directory");
        let index = build_index(
            &[missing, dir.path.clone()],
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_IDENTIFIED,
        );
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn the_index_reports_what_it_looked_at_so_nothing_matched_can_be_explained() {
        let dir = TempDir::new("report");
        dir.write("one.json", &mac_isf(BANNER_A));
        let index = build_index(
            std::slice::from_ref(&dir.path),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_IDENTIFIED,
        );
        let json = index.to_json();
        assert_eq!(json["packs_indexed"], 1);
        assert_eq!(json["files_seen"], 1);
        assert_eq!(json["files_identified"], 1);
        assert_eq!(json["truncated"], false);
    }
}
