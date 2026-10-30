//! Parity for the VAD tree and for the injected-code finding built on top of it.
//!
//! `windows.vadinfo` is the largest oracle in the corpus — 17,405 rows for the
//! Windows 11 capture — which makes it the best available evidence that the tree
//! walk is *right* rather than merely the right length. A walk that descends the
//! wrong pointer, or reads `StartingVpn` at the wrong offset, or composes a
//! split page number the wrong way round, still produces a tidy table of the
//! same size. So nothing here compares counts: it compares the **set** of
//! `(pid, start, end)` triples, and then every other column of every row the two
//! tools have in common. A tree walk that finds the right number of wrong ranges
//! fails.
//!
//! `windows.malfind` is the finding that rests on all of it. Séance has no
//! malfind stage of its own; the criteria are applied here, over
//! [`vad::list_vads`] output and the process's own address space, precisely
//! because that is the claim under test — that the VAD data Séance produces is
//! sufficient and correct enough to reach the same conclusions about injected
//! code as the tool the field already trusts.
//!
//! Two deliberate divergences are asserted rather than tolerated:
//!
//! * **The carry.** Upstream composes a split page number in *address* space as
//!   `(Vpn << 12) | (VpnHigh << 44)`, so when `EndingVpn + 1` carries out of the
//!   low 32 bits the carry is ORed onto the high field instead of added, putting
//!   the end of the range 16 TiB from the truth. `vad.rs` composes in
//!   page-number space and multiplies once. This file finds whether any range in
//!   the corpus reaches the carry, and says which answer is right if one does.
//! * **The dirty page.** Upstream additionally reports an `EXECUTE`-without-
//!   `WRITE` region when any page in it has the page-table dirty bit set.
//!   `seance_memory` does not publish that bit, so Séance cannot reach those
//!   regions. They are named here, individually, rather than quietly absorbed
//!   into a loosened assertion.
//!
//! The images are large and not committed, so these tests skip when the corpus
//! is absent. See the module docs on `tests/common/mod.rs` for the environment.

mod common;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use seance_core::io::read_full;
use seance_memory::translate::TableCache;
use seance_memory::MemoryLayer;
use seance_plugin_memory_windows::process::{self, ProcessListConfig, ProcessSymbols};
use seance_plugin_memory_windows::vad::{
    self, MappedFile, ProtectionTable, Vad, VadKind, VadRootShape, VadStop, VadSymbols, VadTree,
    VadWalkConfig, PAGE_SIZE,
};
use seance_plugin_memory_windows::WindowsProfile;

/// Oracle directory for the Windows XP SP2 capture.
const ORACLE_XP: &str = "oracle";

/// Oracle directory for the Windows 11 22000 capture.
const ORACLE_WIN11: &str = "oracle_win11";

/// How many disagreeing rows a failure message prints before it stops.
///
/// Enough to see the shape of a systematic error — every range one page short,
/// every offset from one process — without burying it in seventeen thousand
/// lines.
const MAX_REPORTED: usize = 20;

// ── Reading the oracle ──────────────────────────────────────────────────────

/// A Volatility CSV, parsed properly.
///
/// The naive `split(',')` that serves the flat oracles cannot read
/// `windows.malfind`: its `Hexdump` column is a quoted field containing both
/// commas and newlines, so a line-oriented reader sees twenty rows as a hundred
/// lines and a comma-splitting reader tears each row into pieces. Counting those
/// lines is exactly how the recorded row counts for malfind came to be 100 and
/// 40 when the plugin emitted 20 and 8.
struct Oracle {
    /// Column names, in the order the CSV declares them.
    columns: Vec<String>,
    /// Data rows. Never the header, never a blank line.
    rows: Vec<Vec<String>>,
}

impl Oracle {
    /// Load `<SEANCE_MEM_IMAGES>/<dir>/<plugin>.csv`, or `None` when the corpus
    /// was never provisioned.
    ///
    /// Once the corpus is present, a missing oracle is a defect: comparing
    /// against an oracle nobody generated used to report `ok`.
    fn load(dir: &str, plugin: &str) -> Option<Oracle> {
        let base = seance_core::test_support::corpus::dir("SEANCE_MEM_IMAGES")?;
        let path = base.join(dir).join(format!("{plugin}.csv"));
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "the corpus is present but the {plugin} oracle at {} could not be read: {e}",
                path.display()
            )
        });
        let mut records = parse_csv(&text);
        if records.is_empty() {
            panic!("{} holds no header, so it is not an oracle", path.display());
        }
        let columns = records.remove(0);
        Some(Oracle {
            columns,
            rows: records,
        })
    }

    /// The index of a named column.
    ///
    /// Panics naming every column the file does have: a renamed column in a new
    /// Volatility release must fail loudly here rather than silently compare
    /// against the wrong field.
    fn index(&self, name: &str) -> usize {
        self.columns
            .iter()
            .position(|column| column == name)
            .unwrap_or_else(|| {
                panic!(
                    "the oracle has no column {name:?}; it has {:?}",
                    self.columns
                )
            })
    }

    /// One field of one row.
    fn field<'a>(&self, row: &'a [String], name: &str) -> &'a str {
        let index = self.index(name);
        row.get(index).map(String::as_str).unwrap_or_else(|| {
            panic!(
                "a row has {} field(s) and column {name:?} is number {index}",
                row.len()
            )
        })
    }
}

/// Split RFC 4180 CSV into records, honouring quoted fields.
///
/// Quoted fields may hold commas, newlines and doubled quotes. A record of one
/// empty field is a blank line and is dropped, which is what keeps a trailing
/// newline from counting as a row.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();

    while let Some(character) = chars.next() {
        if quoted {
            if character == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            } else {
                field.push(character);
            }
            continue;
        }
        match character {
            '"' => quoted = true,
            ',' => record.push(std::mem::take(&mut field)),
            '\r' => {}
            '\n' => {
                record.push(std::mem::take(&mut field));
                push_record(&mut records, std::mem::take(&mut record));
            }
            _ => field.push(character),
        }
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        push_record(&mut records, record);
    }
    records
}

/// Keep a record unless it is a blank line.
fn push_record(records: &mut Vec<Vec<String>>, record: Vec<String>) {
    if record.len() == 1 && record[0].is_empty() {
        return;
    }
    records.push(record);
}

/// A `0x`-prefixed integer from the oracle.
fn hex(field: &str) -> u64 {
    let text = field.trim();
    let digits = text.strip_prefix("0x").unwrap_or(text);
    u64::from_str_radix(digits, 16)
        .unwrap_or_else(|_| panic!("the oracle holds {field:?} where an address belongs"))
}

/// A decimal integer from the oracle.
fn decimal(field: &str) -> u64 {
    field
        .trim()
        .parse::<u64>()
        .unwrap_or_else(|_| panic!("the oracle holds {field:?} where a count belongs"))
}

/// Undo the backslash doubling Volatility's CSV renderer applies to paths.
///
/// `\Windows\System32\ntdll.dll` is written `\\Windows\\System32\\ntdll.dll`.
/// Comparing without undoing it fails every mapped file in the capture.
fn unescape_path(field: &str) -> String {
    field.replace("\\\\", "\\")
}

// ── Walking every process's tree ────────────────────────────────────────────

/// One process's tree, with the identity needed to compare it.
struct WalkedProcess {
    /// `UniqueProcessId`.
    pid: u64,
    /// `ImageFileName`, or a stated absence.
    name: String,
    /// Address of the `_EPROCESS`.
    address: u64,
    /// The tree, when it could be walked at all.
    tree: Option<VadTree>,
    /// Why it could not be, when it could not.
    failure: Option<String>,
}

/// Everything one image's VAD stage produced.
struct Walk {
    /// Per-process trees, in process-list order.
    processes: Vec<WalkedProcess>,
    /// The symbols the walk resolved, kept for the shape assertions.
    symbols: VadSymbols,
}

/// Walk the VAD tree of every process in the active list.
///
/// The garbage entries a smeared `ActiveProcessLinks` chain produces are walked
/// too rather than filtered out first: Volatility walks them as well, and
/// dropping them here would hide a divergence instead of reporting one.
fn walk_every_process(profile: &WindowsProfile) -> Walk {
    let process_symbols = ProcessSymbols::from_profile(profile)
        .expect("both reference builds declare a describable _EPROCESS");
    let list = process::list_processes(profile, &process_symbols, &ProcessListConfig::default())
        .expect("the active process list is walkable on both reference builds");

    let symbols =
        VadSymbols::from_profile(profile).expect("both reference builds declare a VAD layout");
    let protections = ProtectionTable::from_profile(profile).expect(
        "both reference builds publish MmProtectToValue; without it every protection would be \
         unknown and the comparison would be vacuous",
    );
    let config = VadWalkConfig {
        // Raised from the default so that the explanation for an extra range —
        // which node the walk descended through without being able to read its
        // tag — is still on the record for a tree with many gaps.
        max_recorded_skips: 8192,
        protections: Some(Arc::new(protections)),
        ..VadWalkConfig::default()
    };

    let mut processes = Vec::new();
    for record in &list.processes {
        let Some(&pid) = record.pid.known() else {
            continue;
        };
        let name = record
            .image_file_name
            .known()
            .cloned()
            .unwrap_or_else(|| "<name unreadable>".to_string());
        match vad::list_vads(profile, &symbols, record.address, &config) {
            Ok(tree) => processes.push(WalkedProcess {
                pid,
                name,
                address: record.address,
                tree: Some(tree),
                failure: None,
            }),
            Err(err) => processes.push(WalkedProcess {
                pid,
                name,
                address: record.address,
                tree: None,
                failure: Some(err.to_string()),
            }),
        }
    }
    Walk { processes, symbols }
}

/// Whether a range Volatility did not report hangs below a node the walk
/// descended through without being able to name it as a VAD.
///
/// The one documented reason the two walks can differ in this direction.
/// Upstream prunes the whole subtree below a node whose pool tag it could not
/// read, which silently loses every range behind an unacquired page; `vad.rs`
/// descends anyway, does not report the node itself, and records that it did
/// both. A range that cannot be traced back to such a node is not explained by
/// that rule and is an invented allocation.
fn descends_from_a_node_the_walk_could_not_name(tree: &VadTree, vad: &Vad) -> bool {
    let descended: HashSet<u64> = tree
        .skipped
        .iter()
        .filter(|skip| skip.descended)
        .map(|skip| skip.address)
        .collect();
    if descended.is_empty() {
        return false;
    }
    let by_address: HashMap<u64, &Vad> =
        tree.vads.iter().map(|node| (node.address, node)).collect();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut cursor = vad.parent;
    while let Some(address) = cursor {
        if address == 0 || !seen.insert(address) {
            return false;
        }
        if descended.contains(&address) {
            return true;
        }
        cursor = by_address.get(&address).and_then(|node| node.parent);
    }
    false
}

// ── The layout both builds resolve ──────────────────────────────────────────

#[test]
fn each_reference_build_resolves_the_vad_layout_its_kernel_actually_has() {
    if let Some(profile) = common::profile(common::XP) {
        let symbols = VadSymbols::from_profile(&profile).expect("XP declares a VAD layout");
        // XP's `_EPROCESS.VadRoot` is a bare `void *` to the root `_MMVAD`, its
        // children are `LeftChild`/`RightChild`, its page numbers are not split,
        // and its `Parent` carries no balance bits to mask.
        assert_eq!(symbols.root_shape, VadRootShape::Pointer);
        assert_eq!(symbols.left, "LeftChild");
        assert_eq!(symbols.right, "RightChild");
        assert_eq!(symbols.start_vpn_high, None);
        assert_eq!(symbols.end_vpn_high, None);
        assert_eq!(symbols.parent, Some(("Parent".to_string(), false)));
        assert!(symbols.has_long_vad, "XP declares _MMVAD");
        // The tag sits four bytes in front of the node on x86.
        assert_eq!(symbols.tag_distance, 4);
    }

    if let Some(profile) = common::profile(common::WIN11) {
        let symbols = VadSymbols::from_profile(&profile).expect("Windows 11 declares a VAD layout");
        // Windows 11's `VadRoot` is an `_RTL_AVL_TREE` whose `Root` is a real
        // node, its children hang off an embedded `_RTL_BALANCED_NODE`, its page
        // numbers are split across two members, and its parent link packs two
        // bits of tree balance into the bottom of the pointer.
        assert_eq!(symbols.root_shape, VadRootShape::AvlTreeRoot);
        assert_eq!(symbols.left, "VadNode.Left");
        assert_eq!(symbols.right, "VadNode.Right");
        assert_eq!(symbols.start_vpn_high.as_deref(), Some("StartingVpnHigh"));
        assert_eq!(symbols.end_vpn_high.as_deref(), Some("EndingVpnHigh"));
        assert_eq!(
            symbols.parent,
            Some(("VadNode.ParentValue".to_string(), true)),
            "an unmasked ParentValue dereferences three bytes into the parent node"
        );
        // Twelve bytes in front of the node on x64.
        assert_eq!(symbols.tag_distance, 12);
    }
}

// ── windows.vadinfo ─────────────────────────────────────────────────────────

#[test]
fn win11_vadinfo_reports_the_same_memory_ranges_volatility_reports() {
    let Some(oracle) = Oracle::load(ORACLE_WIN11, "windows.vadinfo") else {
        return;
    };
    let Some(profile) = common::profile(common::WIN11) else {
        return;
    };
    let walk = walk_every_process(&profile);

    // ── What Volatility saw ────────────────────────────────────────────────
    //
    // Keyed by the triple, because that is the claim: this process had a range
    // beginning here and ending there. Volatility renders both ends as
    // addresses despite the "VPN" column headings.
    let mut theirs: BTreeMap<(u64, u64, u64), &[String]> = BTreeMap::new();
    let mut theirs_by_start: BTreeMap<(u64, u64), &[String]> = BTreeMap::new();
    for row in &oracle.rows {
        let pid = decimal(oracle.field(row, "PID"));
        let start = hex(oracle.field(row, "Start VPN"));
        let end = hex(oracle.field(row, "End VPN"));
        assert!(
            theirs.insert((pid, start, end), row.as_slice()).is_none(),
            "the oracle lists {start:#x}-{end:#x} for PID {pid} twice, so it cannot be a set"
        );
        theirs_by_start.insert((pid, start), row.as_slice());
    }
    assert_eq!(
        theirs.len(),
        17_405,
        "the oracle is not the one these expectations were taken from"
    );

    // ── What Séance saw ────────────────────────────────────────────────────
    let mut ours: BTreeMap<(u64, u64, u64), (&WalkedProcess, &Vad)> = BTreeMap::new();
    let mut duplicates: Vec<String> = Vec::new();
    let mut walk_failures: Vec<(u64, String)> = Vec::new();
    for walked in &walk.processes {
        let Some(tree) = &walked.tree else {
            let failure = walked.failure.as_deref().unwrap_or("no reason recorded");
            walk_failures.push((
                walked.pid,
                format!(
                    "PID {} ({}) at {:#x}: {failure}",
                    walked.pid, walked.name, walked.address
                ),
            ));
            continue;
        };
        for node in &tree.vads {
            let key = (walked.pid, node.start, node.end);
            if ours.insert(key, (walked, node)).is_some() {
                duplicates.push(format!(
                    "PID {} has {:#x}-{:#x} twice",
                    walked.pid, node.start, node.end
                ));
            }
        }
    }

    // A process whose tree could not be walked at all is only acceptable if
    // Volatility found no ranges for it either. Otherwise ranges are missing and
    // the reason is not a node-level skip but a stage-level refusal.
    let pids_with_ranges: BTreeSet<u64> = theirs.keys().map(|(pid, _, _)| *pid).collect();
    let unexplained_failures: Vec<&String> = walk_failures
        .iter()
        .filter(|(pid, _)| pids_with_ranges.contains(pid))
        .map(|(_, failure)| failure)
        .collect();
    assert!(
        unexplained_failures.is_empty(),
        "the VAD walk refused a process Volatility read ranges from: {unexplained_failures:#?}"
    );
    assert!(
        duplicates.is_empty(),
        "the same range was reported twice for one process, so the walk revisited a node: \
         {duplicates:#?}"
    );

    // ── The carry ──────────────────────────────────────────────────────────
    //
    // `EndingVpn + 1` carries out of the low 32 bits only when the low half is
    // all ones. Upstream ORs that carry onto `EndingVpnHigh` instead of adding
    // it, which lands the end of the range 16 TiB away — but only when the high
    // half is non-zero, since ORing 1 onto 0 and adding 1 to 0 agree.
    let carry_cases: Vec<((u64, u64), u64, &Vad)> = ours
        .iter()
        .filter_map(|(&(pid, start, _), &(_, node))| {
            let end_page = node.end / PAGE_SIZE;
            let carries = end_page & 0xFFFF_FFFF == 0xFFFF_FFFF && end_page >> 32 != 0;
            carries.then(|| {
                // What upstream's address-space composition produces instead:
                // the low half is incremented and shifted into address space on
                // its own, so its carry lands on top of the high field rather
                // than adding to it.
                let low = (end_page & 0xFFFF_FFFF)
                    .saturating_add(1)
                    .saturating_mul(PAGE_SIZE);
                let high = (end_page >> 32).saturating_mul(1u64 << 44);
                ((pid, start), (low | high).saturating_sub(1), node)
            })
        })
        .collect();

    let carry_keys: BTreeSet<(u64, u64)> = carry_cases.iter().map(|(key, _, _)| *key).collect();
    if carry_cases.is_empty() {
        // The corpus does not exercise the carry: no range in this capture ends
        // at a page number whose low 32 bits are all ones with a non-zero high
        // half, which would put its last byte on a 16 TiB boundary. The two
        // compositions must therefore agree on every range below, and the set
        // comparison that follows is exact rather than partial.
        eprintln!("no range in the Windows 11 capture reaches the split-page-number carry");
    } else {
        for ((pid, start), upstream, node) in &carry_cases {
            let row = theirs_by_start.get(&(*pid, *start)).unwrap_or_else(|| {
                panic!("Volatility reported no range beginning at {start:#x} for PID {pid}")
            });
            let their_end = hex(oracle.field(row, "End VPN"));
            assert_eq!(
                their_end, *upstream,
                "PID {pid}'s range at {start:#x} reaches the carry, so Volatility should have \
                 produced the ORed composition"
            );
            assert_ne!(
                node.end, their_end,
                "if the two agree here the carry was not actually reached"
            );
            // `EndingVpn` names the last page in the range, so the last byte is
            // the last byte of that page. This is the arithmetic upstream loses.
            assert_eq!(
                node.end,
                (node.end / PAGE_SIZE)
                    .saturating_add(1)
                    .saturating_mul(PAGE_SIZE)
                    .saturating_sub(1),
                "Séance's end must still be the last byte of the last page"
            );
            eprintln!(
                "documented divergence: PID {pid} range at {start:#x} ends at {:#x}; Volatility \
                 reports {their_end:#x}, which is the carry ORed onto EndingVpnHigh",
                node.end
            );
        }
    }

    // ── The sets ───────────────────────────────────────────────────────────
    let missing_keys: Vec<(u64, u64, u64)> = theirs
        .keys()
        .filter(|(pid, start, _)| !carry_keys.contains(&(*pid, *start)))
        .filter(|key| !ours.contains_key(*key))
        .copied()
        .collect();
    let missing: Vec<String> = missing_keys
        .iter()
        .take(MAX_REPORTED)
        .map(|(pid, start, end)| format!("PID {pid} {start:#x}-{end:#x}"))
        .collect();

    let extra_keys: Vec<(u64, u64, u64)> = ours
        .keys()
        .filter(|(pid, start, _)| !carry_keys.contains(&(*pid, *start)))
        .filter(|key| !theirs.contains_key(*key))
        .copied()
        .collect();

    // An extra range is only acceptable where Séance refused to prune a subtree
    // behind a node it could not name — the one place the two walks are
    // documented to differ. Everything else is an invented allocation.
    let mut unexplained_extras: Vec<String> = Vec::new();
    for key in &extra_keys {
        let (walked, node) = ours[key];
        let tree = walked.tree.as_ref().expect("a walked process has a tree");
        if descends_from_a_node_the_walk_could_not_name(tree, node) {
            continue;
        }
        unexplained_extras.push(format!(
            "PID {} ({}) {:#x}-{:#x} at node {:#x} tag {:?}",
            walked.pid, walked.name, node.start, node.end, node.address, node.tag
        ));
    }

    assert!(
        missing_keys.is_empty(),
        "Séance did not report {} range(s) Volatility did. First {}: {missing:#?}",
        missing_keys.len(),
        missing.len()
    );
    assert!(
        unexplained_extras.is_empty(),
        "Séance reported {} range(s) Volatility did not, and {} of them do not hang below a node \
         the walk was unable to name. First {}: {:#?}",
        extra_keys.len(),
        unexplained_extras.len(),
        unexplained_extras.len().min(MAX_REPORTED),
        unexplained_extras
            .iter()
            .take(MAX_REPORTED)
            .collect::<Vec<_>>()
    );

    // ── Every other column of every shared row ─────────────────────────────
    //
    // Equal sets of ranges would still be consistent with the protection index
    // being read from the wrong bitfield, or the mapped file coming off the
    // neighbouring control area. Those are the columns an examiner acts on.
    let mut disagreements: Vec<String> = Vec::new();
    let mut unavailable_files = 0usize;
    for (key, &row) in &theirs {
        let Some(&(walked, node)) = ours.get(key) else {
            continue;
        };
        let (pid, start, end) = *key;
        let where_ = format!("PID {pid} ({}) {start:#x}-{end:#x}", walked.name);

        let their_offset = hex(oracle.field(row, "Offset"));
        if node.address != their_offset {
            disagreements.push(format!(
                "{where_}: node at {:#x}, Volatility says {their_offset:#x}",
                node.address
            ));
        }
        // `windows.vadinfo` canonicalises the offsets it prints, so unlike
        // `windows.info` these are full 64-bit kernel pointers and comparing
        // them needs no truncation.
        let their_parent = hex(oracle.field(row, "Parent"));
        if node.parent.unwrap_or(0) != their_parent {
            disagreements.push(format!(
                "{where_}: parent {:?}, Volatility says {their_parent:#x}",
                node.parent
            ));
        }
        let their_tag = oracle.field(row, "Tag");
        if node.tag != their_tag {
            disagreements.push(format!(
                "{where_}: tag {:?}, Volatility says {their_tag:?}",
                node.tag
            ));
        }
        let their_protection = oracle.field(row, "Protection");
        if node.protection_names.as_deref().unwrap_or("") != their_protection {
            disagreements.push(format!(
                "{where_}: protection {:?}, Volatility says {their_protection:?}",
                node.protection_names
            ));
        }
        let their_commit = decimal(oracle.field(row, "CommitCharge"));
        if node.commit_charge != Some(their_commit) {
            disagreements.push(format!(
                "{where_}: commit charge {:?}, Volatility says {their_commit}",
                node.commit_charge
            ));
        }
        let their_private = decimal(oracle.field(row, "PrivateMemory")) != 0;
        if node.private_memory != Some(their_private) {
            disagreements.push(format!(
                "{where_}: private memory {:?}, Volatility says {their_private}",
                node.private_memory
            ));
        }

        // Upstream renders "no file mapped", "this is a short VAD" and "the file
        // object could not be read" identically as N/A. Séance keeps the three
        // apart, so the assertion is directional: a named file must match, and a
        // range upstream calls N/A must not acquire a name here.
        let their_file = oracle.field(row, "File");
        // An *empty* File cell is not a path Volatility read. Its string cast
        // truncates a `_UNICODE_STRING` at the first NUL, so a blank means the
        // `_FILE_OBJECT.FileName` buffer began with one — a torn or reused
        // structure, of which this capture has exactly one. It is treated as N/A
        // is: there is nothing to compare, and the only assertion left is that
        // Séance did not publish the damage as a file name.
        if their_file == "N/A" || their_file.is_empty() {
            if let Some(name) = node.file.name() {
                disagreements.push(format!(
                    "{where_}: Séance names {name:?}, and Volatility read no path here ({:?})",
                    their_file
                ));
            }
            if matches!(node.file, MappedFile::Unavailable(_)) {
                unavailable_files += 1;
            }
        } else {
            let expected = unescape_path(their_file);
            if node.file.name() != Some(expected.as_str()) {
                disagreements.push(format!(
                    "{where_}: mapped file {:?}, Volatility says {expected:?}",
                    node.file
                ));
            }
        }

        // A short VAD cannot map a file by construction. Claiming one would mean
        // the long form was read over a structure that is not one.
        if node.kind == VadKind::Short && !matches!(node.file, MappedFile::NotApplicable) {
            disagreements.push(format!(
                "{where_}: a {} VAD reported a file as {:?}",
                node.kind.as_str(),
                node.file
            ));
        }
        // Both ends are page-aligned, the end inclusively. A range that is not
        // is a composition error however well it matches.
        if start % PAGE_SIZE != 0 || end.wrapping_add(1) % PAGE_SIZE != 0 || end < start {
            disagreements.push(format!(
                "{where_}: the range is not a whole number of pages"
            ));
        }
    }

    assert!(
        disagreements.is_empty(),
        "{} row(s) of {} agree on the range and disagree on what it is. First {}: {:#?}",
        disagreements.len(),
        theirs.len(),
        disagreements.len().min(MAX_REPORTED),
        disagreements.iter().take(MAX_REPORTED).collect::<Vec<_>>()
    );

    if unavailable_files > 0 {
        eprintln!(
            "{unavailable_files} range(s) map a file whose name could not be read; Volatility \
             renders these as N/A, which is indistinguishable from mapping no file at all"
        );
    }
}

#[test]
fn win11_a_vad_walk_that_stopped_early_says_so_rather_than_ending_quietly() {
    let Some(profile) = common::profile(common::WIN11) else {
        return;
    };
    let walk = walk_every_process(&profile);

    // A cap that fired is not the end of a tree. If one fires here the range
    // counts above are floors, and every "this process had no such region"
    // conclusion drawn from them is unsupported.
    let capped: Vec<String> = walk
        .processes
        .iter()
        .filter_map(|walked| {
            let tree = walked.tree.as_ref()?;
            match tree.stop {
                VadStop::CapReached { cap } => Some(format!(
                    "PID {} ({}) stopped at its cap of {cap} node(s)",
                    walked.pid, walked.name
                )),
                VadStop::Exhausted => None,
            }
        })
        .collect();
    assert!(
        capped.is_empty(),
        "a VAD walk hit its node cap, so its range list is a floor: {capped:#?}"
    );

    // Where nodes were skipped, the tree must not claim to be complete and must
    // carry something a report can print. An empty result and "could not
    // determine" rendering the same is the failure this whole file exists to
    // prevent.
    for walked in &walk.processes {
        let Some(tree) = &walked.tree else {
            continue;
        };
        if tree.skipped_total == 0 {
            assert!(
                tree.is_complete(),
                "PID {} skipped nothing and stopped at {:?}, yet is not complete",
                walked.pid,
                tree.stop
            );
            continue;
        }
        assert!(
            !tree.is_complete(),
            "PID {} skipped {} node(s) and still calls its tree complete",
            walked.pid,
            tree.skipped_total
        );
        assert!(
            !tree.incomplete().is_empty(),
            "PID {} skipped {} node(s) and declares nothing for a report to print",
            walked.pid,
            tree.skipped_total
        );
    }

    // The root of a tree Volatility read ranges from is a real node, not a
    // sentinel: on this build `VadRoot.Root` points at the first VAD.
    assert_eq!(walk.symbols.root_shape, VadRootShape::AvlTreeRoot);
    let with_ranges = walk
        .processes
        .iter()
        .filter(|walked| {
            walked
                .tree
                .as_ref()
                .is_some_and(|tree| !tree.vads.is_empty())
        })
        .count();
    assert_eq!(
        with_ranges, 98,
        "Volatility reports ranges for 98 of the processes in this capture"
    );
}

// ── windows.malfind ─────────────────────────────────────────────────────────

/// Bytes read at a time when deciding whether a region holds anything.
const CHUNK: u64 = 0x1000;

/// Ceiling on chunks read from one region.
///
/// Upstream has no ceiling: it will read a gigabyte of zeros to decide a region
/// is empty. A bound is needed here so a corrupt range cannot stall the suite,
/// but a bound that fires must not be reported as "empty" — that would drop a
/// region from the finding on the strength of not having looked. It becomes
/// [`Emptiness::Undetermined`], which the tests assert never happens on this
/// corpus.
const MAX_CHUNKS: u64 = 65_536;

/// Whether a region holds anything an examiner could disassemble.
enum Emptiness {
    /// Every readable byte is zero, and every byte was looked at.
    Empty,
    /// At least one non-zero byte.
    HasData,
    /// Not enough of the region was readable to say either way.
    Undetermined(String),
}

/// Decide whether a VAD's range is entirely zero or unavailable.
///
/// The mirror of upstream's `is_vad_empty`: pages that are not resident are
/// skipped rather than counted as zeros, and a single non-zero byte ends the
/// scan. The difference is that running out of budget is a third answer here
/// rather than silently becoming the first.
fn region_emptiness(layer: &Arc<dyn MemoryLayer>, start: u64, end: u64) -> Emptiness {
    let size = end.saturating_sub(start).saturating_add(1);
    let chunks = size.div_ceil(CHUNK);
    let scan = chunks.min(MAX_CHUNKS);
    let mut buffer = vec![0u8; CHUNK as usize];

    for index in 0..scan {
        let Some(offset) = index.checked_mul(CHUNK).and_then(|d| start.checked_add(d)) else {
            return Emptiness::Undetermined(format!(
                "the range beginning at {start:#x} runs past the end of the address space"
            ));
        };
        if !layer.is_valid(offset, CHUNK) {
            continue;
        }
        let read = read_full(layer.as_data_source(), offset, &mut buffer) as u64;
        if read != CHUNK {
            return Emptiness::Undetermined(format!(
                "the page at {offset:#x} is mapped and only {read} of {CHUNK} byte(s) could be read"
            ));
        }
        if buffer.iter().any(|&byte| byte != 0) {
            return Emptiness::HasData;
        }
    }
    if chunks > scan {
        return Emptiness::Undetermined(format!(
            "only {scan} of {chunks} page(s) of the range at {start:#x} were examined"
        ));
    }
    Emptiness::Empty
}

/// One region Séance would report as possibly holding injected code.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Injection {
    /// The process it belongs to.
    pid: u64,
    /// First byte of the range.
    start: u64,
    /// Last byte of the range, inclusive.
    end: u64,
    /// `ImageFileName`.
    process: String,
    /// The pool tag in front of the VAD.
    tag: String,
    /// The protection the kernel's own table names.
    protection: String,
}

/// The outcome of scanning one image for injected code.
struct InjectionScan {
    /// Regions that meet the criteria and hold data.
    reported: Vec<Injection>,
    /// Regions whose status could not be decided, which must be empty for the
    /// set comparison against the oracle to mean anything.
    undetermined: Vec<String>,
    /// Regions upstream can reach only through the page-table dirty bit:
    /// executable, not writable, and therefore outside what Séance can see.
    execute_without_write: usize,
}

/// Apply upstream's injected-code criteria to Séance's VAD output.
///
/// Everything but the dirty-page branch, which needs a page-table bit
/// `seance_memory` does not publish. What is applied:
///
/// * the protection must name both `EXECUTE` and `WRITE`;
/// * the range must be private memory in a `VadS`, or shared memory whose
///   protection is not `PAGE_EXECUTE_WRITECOPY` — the ordinary protection of a
///   mapped image's code, which would otherwise report every loaded DLL;
/// * the range must hold at least one non-zero byte.
fn scan_for_injections(profile: &WindowsProfile) -> InjectionScan {
    let process_symbols =
        ProcessSymbols::from_profile(profile).expect("a describable _EPROCESS layout");
    let list = process::list_processes(profile, &process_symbols, &ProcessListConfig::default())
        .expect("the active process list is walkable");
    let symbols = VadSymbols::from_profile(profile).expect("a describable VAD layout");
    let protections = ProtectionTable::from_profile(profile)
        .expect("MmProtectToValue, without which no region could be called executable");
    let config = VadWalkConfig {
        protections: Some(Arc::new(protections)),
        ..VadWalkConfig::default()
    };
    let cache = Arc::new(TableCache::new());

    let mut scan = InjectionScan {
        reported: Vec::new(),
        undetermined: Vec::new(),
        execute_without_write: 0,
    };

    for record in &list.processes {
        let Some(&pid) = record.pid.known() else {
            continue;
        };
        let name = record
            .image_file_name
            .known()
            .cloned()
            .unwrap_or_else(|| "<name unreadable>".to_string());
        let Ok(tree) = vad::list_vads(profile, &symbols, record.address, &config) else {
            // A process whose tree cannot be walked contributes no findings, and
            // the vadinfo test above is what proves that is not happening to a
            // process with ranges.
            continue;
        };

        // Which of this process's ranges are candidates, before any of its
        // memory is read. Building the process's address space is only worth
        // doing when there is something in it to look at.
        let mut candidates: Vec<&Vad> = Vec::new();
        for node in &tree.vads {
            let Some(protection) = node.protection_names.as_deref() else {
                if node.protection.is_some() {
                    scan.undetermined.push(format!(
                        "PID {pid} ({name}) {:#x}-{:#x}: protection index {:?} names no \
                         protection, so it cannot be called executable or not",
                        node.start, node.end, node.protection
                    ));
                }
                continue;
            };
            let executable = protection.contains("EXECUTE");
            let writable = protection.contains("WRITE");
            if !executable {
                continue;
            }
            if !writable {
                // Upstream reaches these through the page-table dirty bit.
                scan.execute_without_write += 1;
                continue;
            }
            let Some(private) = node.private_memory else {
                scan.undetermined.push(format!(
                    "PID {pid} ({name}) {:#x}-{:#x}: whether the range is private could not be \
                     read, so the criteria cannot be applied",
                    node.start, node.end
                ));
                continue;
            };
            let qualifies = (private && node.tag == "VadS")
                || (!private && protection != "PAGE_EXECUTE_WRITECOPY");
            if qualifies {
                candidates.push(node);
            }
        }
        if candidates.is_empty() {
            continue;
        }

        let layer =
            match process::process_address_space(profile, &process_symbols, record.address, &cache)
            {
                Ok(layer) => layer,
                Err(err) => {
                    for node in &candidates {
                        scan.undetermined.push(format!(
                            "PID {pid} ({name}) {:#x}-{:#x}: the process has no readable address \
                         space, so whether the region holds anything is unknown: {err}",
                            node.start, node.end
                        ));
                    }
                    continue;
                }
            };

        for node in candidates {
            let protection = node
                .protection_names
                .as_deref()
                .expect("a candidate has a named protection")
                .to_string();
            match region_emptiness(&layer, node.start, node.end) {
                Emptiness::HasData => scan.reported.push(Injection {
                    pid,
                    start: node.start,
                    end: node.end,
                    process: name.clone(),
                    tag: node.tag.clone(),
                    protection,
                }),
                Emptiness::Empty => {}
                Emptiness::Undetermined(reason) => scan.undetermined.push(format!(
                    "PID {pid} ({name}) {:#x}-{:#x}: {reason}",
                    node.start, node.end
                )),
            }
        }
    }

    scan.reported.sort();
    scan
}

/// A region upstream reported that Séance's criteria cannot reach.
#[derive(Debug)]
struct DirtyPageRegion {
    /// The process it belongs to.
    pid: u64,
    /// `ImageFileName`, as the oracle renders it.
    process: String,
    /// First byte of the range.
    start: u64,
    /// Last byte of the range, inclusive.
    end: u64,
    /// The protection the oracle names, which is executable and not writable.
    protection: String,
}

/// The oracle's malfind rows, split by whether Séance's criteria can reach them.
struct MalfindOracle {
    /// `(pid, start)` for rows whose protection names both EXECUTE and WRITE.
    write_executable: BTreeSet<(u64, u64)>,
    /// Rows upstream reached only through the page-table dirty bit.
    dirty_page_only: Vec<DirtyPageRegion>,
}

/// Read `windows.malfind` and separate the two ways upstream reaches a region.
fn malfind_oracle(oracle: &Oracle) -> MalfindOracle {
    let mut write_executable = BTreeSet::new();
    let mut dirty_page_only = Vec::new();
    for row in &oracle.rows {
        let pid = decimal(oracle.field(row, "PID"));
        let start = hex(oracle.field(row, "Start VPN"));
        let end = hex(oracle.field(row, "End VPN"));
        let protection = oracle.field(row, "Protection");
        let process = oracle.field(row, "Process");
        if protection.contains("EXECUTE") && protection.contains("WRITE") {
            assert!(
                write_executable.insert((pid, start)),
                "the oracle reports PID {pid}'s region at {start:#x} twice"
            );
        } else {
            assert!(
                protection.contains("EXECUTE"),
                "PID {pid} ({process}) {start:#x}-{end:#x} is neither writable nor executable, so \
                 upstream had no criterion that could have reported it: {protection:?}"
            );
            dirty_page_only.push(DirtyPageRegion {
                pid,
                process: process.to_string(),
                start,
                end,
                protection: protection.to_string(),
            });
        }
    }
    MalfindOracle {
        write_executable,
        dirty_page_only,
    }
}

/// Compare a scan with the write-executable part of the oracle, naming which
/// regions differ.
fn assert_injections_match(scan: &InjectionScan, expected: &BTreeSet<(u64, u64)>) {
    assert!(
        scan.undetermined.is_empty(),
        "{} region(s) could not be judged, so a set comparison would be comparing how far each \
         tool got. First {}: {:#?}",
        scan.undetermined.len(),
        scan.undetermined.len().min(MAX_REPORTED),
        scan.undetermined
            .iter()
            .take(MAX_REPORTED)
            .collect::<Vec<_>>()
    );

    let ours: BTreeSet<(u64, u64)> = scan
        .reported
        .iter()
        .map(|injection| (injection.pid, injection.start))
        .collect();
    let described: BTreeMap<(u64, u64), &Injection> = scan
        .reported
        .iter()
        .map(|injection| ((injection.pid, injection.start), injection))
        .collect();

    let missing: Vec<String> = expected
        .difference(&ours)
        .map(|(pid, start)| format!("PID {pid} at {start:#x}"))
        .collect();
    let extra: Vec<String> = ours
        .difference(expected)
        .map(|key| {
            let injection = described[key];
            format!(
                "PID {} ({}) at {:#x}-{:#x} {} {}",
                injection.pid,
                injection.process,
                injection.start,
                injection.end,
                injection.tag,
                injection.protection
            )
        })
        .collect();

    assert!(
        missing.is_empty() && extra.is_empty(),
        "the injected-code findings disagree with Volatility. Volatility found and Séance did \
         not: {missing:#?}. Séance found and Volatility did not: {extra:#?}"
    );
}

#[test]
fn win11_malfind_reports_the_same_injected_regions_volatility_reports() {
    let Some(oracle) = Oracle::load(ORACLE_WIN11, "windows.malfind") else {
        return;
    };
    let Some(profile) = common::profile(common::WIN11) else {
        return;
    };
    let expected = malfind_oracle(&oracle);

    // Every region upstream reports in this capture is both writable and
    // executable, so the dirty-page branch Séance cannot follow contributes
    // nothing here and the comparison is total.
    assert!(
        expected.dirty_page_only.is_empty(),
        "this capture does exercise the dirty-page branch after all: {:#?}",
        expected.dirty_page_only
    );
    assert_eq!(
        expected.write_executable.len(),
        8,
        "the oracle is not the one this expectation was taken from"
    );

    let scan = scan_for_injections(&profile);
    assert_injections_match(&scan, &expected.write_executable);

    // Nothing above would fail if every region came back empty and the oracle
    // were empty too. It is not: these are real regions with real bytes in them.
    assert_eq!(scan.reported.len(), 8);
    for injection in &scan.reported {
        assert_eq!(
            injection.protection, "PAGE_EXECUTE_READWRITE",
            "PID {} at {:#x} is reported on a protection the oracle does not name",
            injection.pid, injection.start
        );
        assert_eq!(injection.tag, "VadS");
    }
}

#[test]
fn xp_malfind_reports_every_writable_executable_region_volatility_reports() {
    let Some(oracle) = Oracle::load(ORACLE_XP, "windows.malfind") else {
        return;
    };
    let Some(profile) = common::profile(common::XP) else {
        return;
    };
    let expected = malfind_oracle(&oracle);
    assert_eq!(
        expected.write_executable.len() + expected.dirty_page_only.len(),
        20,
        "the oracle is not the one this expectation was taken from"
    );

    let scan = scan_for_injections(&profile);
    assert_injections_match(&scan, &expected.write_executable);
    assert!(
        !scan.reported.is_empty(),
        "a comparison against an empty finding proves nothing"
    );

    // The capture holds executable, non-writable ranges, which is what makes the
    // dirty-page branch upstream has and Séance does not a real gap rather than
    // a theoretical one. The size of the gap belongs in the record.
    assert!(
        scan.execute_without_write >= expected.dirty_page_only.len(),
        "Volatility reported {} execute-without-write region(s) and Séance saw only {} such \
         range(s) in the whole capture, so the two are not looking at the same tree",
        expected.dirty_page_only.len(),
        scan.execute_without_write
    );
    eprintln!(
        "{} executable, non-writable range(s) were passed over; upstream reaches {} of them \
         through the page-table dirty bit",
        scan.execute_without_write,
        expected.dirty_page_only.len()
    );
}

#[test]
fn xp_the_regions_only_a_dirty_page_bit_reaches_are_named_rather_than_absorbed() {
    let Some(oracle) = Oracle::load(ORACLE_XP, "windows.malfind") else {
        return;
    };
    let expected = malfind_oracle(&oracle);

    // Upstream reports an executable, non-writable region when any page in it
    // carries the page-table dirty bit — the signature of an injection written
    // through an elevated `WriteProcessMemory`. `seance_memory` does not publish
    // that bit, so Séance cannot reach these regions at all. That is a gap, and
    // the point of this test is that it is a *stated* gap with the affected
    // regions listed, rather than a looser assertion that hides it.
    assert!(
        !expected.dirty_page_only.is_empty(),
        "this capture no longer exercises the dirty-page branch, so the divergence recorded here \
         is no longer real and this test is asserting nothing"
    );
    eprintln!(
        "{} region(s) in the XP capture are reachable only through the page-table dirty bit, \
         which Séance does not read:\n{:#?}",
        expected.dirty_page_only.len(),
        expected.dirty_page_only
    );

    // Every one of them is executable and not writable. If one were writable it
    // would be inside Séance's criteria after all, and its absence would be a
    // defect rather than a documented limit.
    for region in &expected.dirty_page_only {
        assert!(
            region.protection.contains("EXECUTE") && !region.protection.contains("WRITE"),
            "PID {} ({}) {:#x}-{:#x} is {}, not an execute-without-write region, so the dirty bit \
             is not why Séance misses it",
            region.pid,
            region.process,
            region.start,
            region.end,
            region.protection
        );
    }
    assert!(
        !expected.write_executable.is_empty(),
        "the capture must also hold regions Séance can reach, or the parity test above is vacuous"
    );
}
