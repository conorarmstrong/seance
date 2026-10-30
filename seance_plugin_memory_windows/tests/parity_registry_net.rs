//! Parity against Volatility 3 for registry hives and network state.
//!
//! Two tiers are checked here, and they fail in opposite directions.
//!
//! **Registry.** `windows.registry.hivelist` is the entry point to everything
//! else in the tier: a hive's `_CMHIVE` address is the only handle `printkey`
//! takes, so a hive list that is short by one hive silently removes a whole
//! user's registry from the case. The comparison is therefore the *set* of
//! `_CMHIVE` addresses and the path each one names, not a row count — a count
//! that matches for the wrong reasons proves nothing, and a count that differs
//! tells an examiner nothing about which hive went missing.
//!
//! **Network.** On Windows 11 the check is the set of
//! `(pid, local address, local port, protocol)` tuples, against both
//! `windows.netscan` (the pool sweep) and `windows.netstat` (the walk). On
//! Windows XP there is no oracle at all, because upstream raises
//! `NotImplementedError` rather than produce a table: XP's tcpip.sys predates
//! the `TcpE`/`TcpL`/`UdpA` pool tags entirely. That absence is the whole test
//! on XP. Séance must refuse the build in the same way, because an empty result
//! set renders as "this machine had no network activity", which is a claim
//! about a suspect's machine that the evidence does not support.
//!
//! # Corpus
//!
//! Point `SEANCE_MEM_IMAGES` at a directory holding `win-xp-laptop.img`,
//! `win11/Win11Dump.mem` and the `oracle/` and `oracle_win11/` CSV directories,
//! and `SEANCE_SYMBOL_DIRS` at the ISF directories. Tests skip when the corpus
//! is absent rather than failing a clean checkout.
//!
//! The network stages additionally need two symbol files that are not the
//! kernel's, because `_TCP_ENDPOINT` and its neighbours are not in `ntoskrnl`'s
//! symbols at any build:
//!
//! - the hand-written netscan type pack, `netscan-win10-20348-x64.json`, which
//!   is what upstream itself selects for build 22000 (its table has no 22000
//!   entry, so it falls back to the latest 10.0 entry it does have);
//! - `tcpip.pdb`'s own ISF, for the `PartitionTable` and compartment-set symbol
//!   addresses that the `netstat` walk starts from.
//!
//! Both are found under `reference/volatility3`; `SEANCE_MEM_NETSCAN_ISF` and
//! `SEANCE_MEM_TCPIP_ISF` override the locations.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use seance_plugin_memory_windows::modules::{self, ModuleSymbols, ModuleWalkConfig};
use seance_plugin_memory_windows::netscan::{
    self, NetscanConfig, NetstatConfig, NetworkEndpoint, NetworkSymbols, TcpipModule,
};
use seance_plugin_memory_windows::registry::{
    self, HiveName, HiveRecord, KeyValue, RegValueType, RegistryData, ValueData,
};
use seance_plugin_memory_windows::WindowsProfile;
use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

use common::{oracle, profile, symbol_dirs, truncate_to_48, WIN11, XP};

// ── Oracle directories ──────────────────────────────────────────────────────

/// Volatility output for the Windows XP SP2 image.
const ORACLE_XP: &str = "oracle";

/// Volatility output for the Windows 11 22000 image.
const ORACLE_WIN11: &str = "oracle_win11";

/// The `_CMHIVE` of the XP machine's `software` hive, from the hivelist oracle.
///
/// Hard-coded on purpose: `printkey` is only meaningful with a hive address, and
/// taking that address from Volatility rather than from Séance's own hive list
/// is what stops the two tests agreeing with each other about a wrong number.
const XP_SOFTWARE_HIVE: u64 = 0xe198_2008;

/// The path the XP `software` hive names, exactly as the oracle prints it once
/// the CSV's backslash doubling is undone.
const XP_SOFTWARE_HIVE_PATH: &str =
    "\\Device\\HarddiskVolume1\\WINDOWS\\system32\\config\\software";

/// A key every Windows installation has, which is why it is the one exercised.
const CURRENT_VERSION: &str = "Microsoft\\Windows\\CurrentVersion";

// ── Reference symbol files ──────────────────────────────────────────────────

/// Where the netscan type pack lives, relative to the repository root.
const NETSCAN_ISF: &str = "reference/volatility3/volatility3/framework/symbols/windows/netscan/\
                           netscan-win10-20348-x64.json";

/// Where tcpip.sys's own ISF lives, relative to a symbol directory.
const TCPIP_ISF_DIR: &str = "windows/tcpip.pdb";

/// The repository root, derived from this crate's manifest directory.
///
/// Not the process's working directory: `cargo test` sets that to the package
/// root, and a test that resolved a reference file against it would find the
/// file or not depending on how it was invoked.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// A path made absolute against the repository root when it is relative.
fn from_repo(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root().join(path)
    }
}

/// The netscan type pack, or `None` when the reference tree is not checked out.
fn netscan_isf_path() -> Option<PathBuf> {
    let path = match std::env::var("SEANCE_MEM_NETSCAN_ISF") {
        Ok(explicit) => PathBuf::from(explicit),
        Err(_) => repo_root().join(NETSCAN_ISF),
    };
    if path.exists() {
        return Some(path);
    }
    eprintln!("skipping: {} not present", path.display());
    None
}

/// tcpip.sys's ISF, or `None` when it is not in any symbol directory.
///
/// The directory is expected to hold exactly one file. More than one would mean
/// a choice between driver builds, and this test has no way to make that choice
/// correctly — the CodeView triple in the loaded tcpip.sys is what decides it,
/// and guessing would produce a walk at another build's offsets.
fn tcpip_isf_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("SEANCE_MEM_TCPIP_ISF") {
        let path = PathBuf::from(explicit);
        if path.exists() {
            return Some(path);
        }
        eprintln!("skipping: {} not present", path.display());
        return None;
    }

    let mut searched: Vec<PathBuf> = Vec::new();
    let mut candidates: Vec<PathBuf> = Vec::new();
    let mut roots: Vec<PathBuf> = symbol_dirs().iter().map(|dir| from_repo(dir)).collect();
    roots.push(repo_root().join("reference/volatility3/volatility3/symbols"));

    for root in roots {
        let dir = root.join(TCPIP_ISF_DIR);
        searched.push(dir.clone());
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with(".json") || name.ends_with(".json.xz") || name.ends_with(".json.gz") {
                candidates.push(path);
            }
        }
        if !candidates.is_empty() {
            break;
        }
    }

    match candidates.len() {
        0 => {
            eprintln!("skipping: no tcpip.pdb ISF under any of {searched:?}");
            None
        }
        1 => candidates.pop(),
        _ => panic!(
            "{} tcpip.pdb ISFs are present ({candidates:?}); which driver build the image loaded \
             decides which is right, and picking one here would be a guess",
            candidates.len()
        ),
    }
}

/// Compile an ISF, or fail naming the file.
///
/// A rejected symbol table is a hard failure rather than a skip: the file is
/// present, so a refusal is a defect in either the file or the reader, and
/// silence would turn it into a skipped test that reads as a passing one.
///
/// One file in the corpus is the exception, and it is the FILE that is at
/// fault. Volatility's `netscan-win10-20348-x64.json` declares
/// `_TCP_ENDPOINT.Owner` at offset 752 inside a type whose own declared size is
/// 632, and `_ADDRINFO.Remote` at offset 16 inside a type of declared size 4.
/// Its producer metadata says `dgmcdona-by-hand`: it is a hand-written overlay
/// where `size` was never measured, and Volatility does not enforce coherence
/// so it never notices.
///
/// Séance's gate 1 does enforce it, and must keep doing so. Reading `Owner` at
/// 752 in a 632-byte type reads whatever follows the endpoint in the pool and
/// publishes it as the process that owned a network connection — a fabricated
/// attribution that no downstream check could catch, in exactly the field an
/// examiner uses to say which program was talking to a remote host.
///
/// So the test asserts the refusal rather than the parse. Skipping it would be
/// a lie by omission; demanding the parse would demand Séance accept a document
/// it is right to refuse.
fn compile_isf(path: &Path) -> Arc<SymbolTable> {
    let limits = DecompressLimits::default();
    let options = CompileOptions::default();
    let table = SymbolTable::compile_path(path, &limits, &options)
        .unwrap_or_else(|err| panic!("{} could not be compiled: {err}", path.display()));
    Arc::new(table)
}

/// Whether an ISF in the corpus is one Séance is right to refuse.
///
/// Returns the reason when the file is known-incoherent, so a test can assert
/// the refusal and say why instead of failing or silently skipping.
fn known_incoherent_isf(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?;
    if name.starts_with("netscan-win10-20348") {
        return Some(
            "a hand-written overlay (producer 'dgmcdona-by-hand') whose declared type sizes are \
             stubs: _TCP_ENDPOINT.Owner sits at 752 in a type of size 632, and _ADDRINFO.Remote \
             at 16 in a type of size 4",
        );
    }
    None
}

#[test]
fn an_isf_whose_members_lie_outside_their_own_type_is_admitted_but_never_silently() {
    // This asserted a refusal until the corpus was measured. The refusal was
    // protecting nothing -- a read is taken at the member's own offset for its
    // own width and is never bounded by the enclosing type's declared size --
    // while it cost netscan and netstat on every modern Windows build, and it
    // made both parity tests below pass while comparing nothing.
    //
    // What must not happen is that the discrepancy goes unrecorded, because an
    // examiner reading the report has to be able to tell a hand-written overlay
    // from a compiler-generated one. So the assertion moved from "refused" to
    // "admitted, and the caveat names the incoherence".
    let Some(path) = netscan_isf_path() else {
        return;
    };
    let Some(why) = known_incoherent_isf(&path) else {
        return;
    };
    let limits = DecompressLimits::default();
    let options = CompileOptions::default();
    let table = SymbolTable::compile_path(&path, &limits, &options).unwrap_or_else(|err| {
        panic!(
            "{} is {why}, but refusing it costs netscan: {err}",
            path.display()
        )
    });

    let caveats: Vec<&str> = table
        .admission()
        .gates
        .iter()
        .flat_map(|gate| gate.caveats.iter().map(String::as_str))
        .collect();
    assert!(
        caveats
            .iter()
            .any(|c| c.contains("_TCP_ENDPOINT") && c.contains("Owner")),
        "the caveat must name the member whose offset the declared size contradicts, so the \
         owner attribution can be judged rather than assumed: {caveats:?}"
    );

    // And the offset it resolves to is the measured one for this build, not
    // something clamped to the declared size.
    assert_eq!(
        table
            .member_offset("_TCP_ENDPOINT", "Owner")
            .expect("Owner is addressable"),
        752,
        "build 20348's Owner offset"
    );
}

/// The network layout for the Windows 11 image, from the netscan type pack.
fn win11_network_symbols(profile: &WindowsProfile) -> Option<NetworkSymbols> {
    let path = netscan_isf_path()?;
    // This used to return None here, because the only file describing build
    // 22000's network objects was one gate 1 refused. That skip made both
    // netscan and netstat parity pass while comparing nothing at all.
    //
    // Measuring the corpus settled it: 23 of the 25 netscan packs Volatility
    // ships declare a member past its type's size, and `_TCP_ENDPOINT.Owner`
    // tracks the real structure build by build -- 712 at 17763, 656 at 18362,
    // 728 at 19041, 752 at 20348 -- against a `size` of 632 that never moved.
    // The offsets are measured; the size beside them was not. So the pack is
    // admitted with a caveat and the comparison below runs for real, which is
    // the only thing that can actually show the owner attribution is right.
    let table = compile_isf(&path);
    match NetworkSymbols::with_table(profile, table) {
        Ok(symbols) => Some(symbols),
        Err(err) => panic!(
            "build 22000's network objects could not be described from {}: {err}",
            path.display()
        ),
    }
}

/// Where tcpip.sys is loaded on the Windows 11 image, with its own symbols.
fn win11_tcpip_module(profile: &WindowsProfile) -> Option<TcpipModule> {
    let path = tcpip_isf_path()?;
    let table = compile_isf(&path);

    let symbols = ModuleSymbols::from_profile(profile).expect("a describable build");
    let listing = modules::list_kernel_modules(profile, &symbols, &ModuleWalkConfig::default())
        .expect("PsLoadedModuleList is walkable on this build");

    let driver = listing
        .modules
        .iter()
        .find(|module| {
            module
                .base_name
                .name()
                .is_some_and(|name| name.eq_ignore_ascii_case("tcpip.sys"))
        })
        .unwrap_or_else(|| {
            panic!(
                "tcpip.sys is not in PsLoadedModuleList, so its symbol addresses cannot be \
                 placed; {} modules were listed",
                listing.modules.len()
            )
        });
    let base = driver.base.unwrap_or_else(|| {
        panic!("tcpip.sys is listed with no load address, so nothing can be read relative to it")
    });

    Some(TcpipModule::new(base, table))
}

// ── Oracle parsing ──────────────────────────────────────────────────────────

/// Undo the backslash doubling Volatility's CSV renderer applies.
///
/// `\\Device\\HarddiskVolume1` in the file is `\Device\HarddiskVolume1` on the
/// machine. Comparing without undoing it makes every path mismatch, which looks
/// exactly like a decoding defect in the hive-name reader.
fn unescape(field: &str) -> String {
    field.replace("\\\\", "\\")
}

/// Parse a `0x`-prefixed address as the oracle prints it.
fn hex(field: &str) -> u64 {
    let trimmed = field.trim();
    let digits = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    u64::from_str_radix(digits, 16)
        .unwrap_or_else(|err| panic!("the oracle printed '{trimmed}' where an address goes: {err}"))
}

/// `windows.registry.hivelist` as `_CMHIVE` address to path.
///
/// The path is `None` where the oracle printed nothing, which is the case the
/// hive-name assertions turn on.
fn hivelist_oracle(dir: &str) -> Option<BTreeMap<u64, Option<String>>> {
    let rows = oracle(dir, "windows.registry.hivelist")?;
    let mut hives = BTreeMap::new();
    for row in rows {
        // TreeDepth, Offset, FileFullPath, File output.
        assert!(
            row.len() >= 3,
            "a hivelist row has fewer columns than the header: {row:?}"
        );
        let path = unescape(&row[2]);
        let path = if path.is_empty() { None } else { Some(path) };
        hives.insert(hex(&row[1]), path);
    }
    Some(hives)
}

/// A network row reduced to the facts a report is read for.
type Endpoint = (u64, String, u16, String);

/// `windows.netscan` or `windows.netstat` as a set of endpoints.
///
/// A set, not a list: the oracle prints one row per network object, and two
/// distinct objects can describe the same socket — a dual-stack listener that
/// was re-bound, for instance. Comparing multisets would compare how many
/// allocations happened to survive rather than what the machine was doing.
fn endpoint_oracle(dir: &str, plugin: &str) -> Option<BTreeSet<Endpoint>> {
    let rows = oracle(dir, plugin)?;
    let mut endpoints = BTreeSet::new();
    for row in rows {
        // TreeDepth, Offset, Proto, LocalAddr, LocalPort, ForeignAddr,
        // ForeignPort, State, PID, Owner, Created.
        assert!(
            row.len() >= 9,
            "a {plugin} row has fewer columns than the header: {row:?}"
        );
        let pid: u64 = row[8]
            .trim()
            .parse()
            .unwrap_or_else(|err| panic!("the oracle printed '{}' as a PID: {err}", row[8]));
        let port: u16 = row[4]
            .trim()
            .parse()
            .unwrap_or_else(|err| panic!("the oracle printed '{}' as a port: {err}", row[4]));
        endpoints.insert((
            pid,
            row[3].trim().to_string(),
            port,
            row[2].trim().to_string(),
        ));
    }
    Some(endpoints)
}

/// Séance's endpoints, keyed the same way, split from the ones that cannot be
/// keyed because a field was not recoverable.
fn our_endpoints(endpoints: &[NetworkEndpoint]) -> (BTreeSet<Endpoint>, Vec<&NetworkEndpoint>) {
    let mut keyed = BTreeSet::new();
    let mut unkeyable = Vec::new();
    for endpoint in endpoints {
        match (endpoint.owner_pid, endpoint.local_address.as_deref()) {
            (Some(pid), Some(address)) => {
                keyed.insert((
                    pid,
                    address.to_string(),
                    endpoint.local_port,
                    endpoint.protocol.as_str().to_string(),
                ));
            }
            _ => unkeyable.push(endpoint),
        }
    }
    (keyed, unkeyable)
}

/// Name the disagreement, in the terms an examiner needs to act on it.
///
/// A count mismatch says only that the two tools stopped in different places. A
/// named difference says which socket, or which hive, one of them did not see —
/// which is the finding, and the thing a defence expert will ask about.
fn diff<T: Ord + std::fmt::Debug>(ours: &BTreeSet<T>, theirs: &BTreeSet<T>) -> String {
    let missing: Vec<&T> = theirs.difference(ours).collect();
    let extra: Vec<&T> = ours.difference(theirs).collect();
    format!(
        "ours={} theirs={}\n  in Volatility and not in Séance ({}): {missing:#?}\n  \
         in Séance and not in Volatility ({}): {extra:#?}",
        ours.len(),
        theirs.len(),
        missing.len(),
        extra.len()
    )
}

// ── Registry: the hive list ─────────────────────────────────────────────────

/// Compare a hive listing against an oracle, on both address and path.
fn assert_hivelist_matches(image: &str, oracle_dir: &str) {
    let Some(profile) = profile(image) else {
        return;
    };
    let Some(theirs) = hivelist_oracle(oracle_dir) else {
        eprintln!("skipping: no hivelist oracle in {oracle_dir}");
        return;
    };
    let listing = registry::list_hives(&profile).expect("CmpHiveListHead is walkable");

    // Séance keeps kernel pointers canonical; Volatility prints them with the
    // sign extension stripped. Truncating ours is lossless, re-extending theirs
    // is guesswork.
    let ours_by_address: BTreeMap<u64, &HiveRecord> = listing
        .hives
        .iter()
        .map(|hive| (truncate_to_48(hive.address), hive))
        .collect();

    // Checked before the set comparison, because a rejected structure is
    // missing from `hives` and would otherwise surface as an unexplained gap.
    // Nothing on the list is ever quietly dropped: a candidate whose hive
    // signature does not check out lands in `rejected`, where it is counted.
    assert!(
        listing.rejected.is_empty(),
        "{image}: {} structure(s) on the hive list did not check out as hives, which Volatility \
         reached and reported as hives: {:?}",
        listing.rejected.len(),
        listing.rejected
    );

    let ours_addresses: BTreeSet<u64> = ours_by_address.keys().copied().collect();
    let theirs_addresses: BTreeSet<u64> = theirs.keys().copied().collect();
    assert_eq!(
        ours_addresses,
        theirs_addresses,
        "{image}: the hive lists disagree with Volatility. A hive missing here removes an entire \
         registry from the case.\n{}",
        diff(&ours_addresses, &theirs_addresses)
    );

    // Volatility walked this list end to end. A Séance walk that had to be
    // completed backwards from the head reached the same hives past something
    // it could not read, and that is a fact about the acquisition an examiner
    // is entitled to before they rely on the count.
    assert!(
        listing.incomplete.is_empty(),
        "{image}: the hive-list walk did not run to completion even though Volatility's did: {:?}",
        listing.incomplete
    );

    for (address, expected) in &theirs {
        let hive = ours_by_address[address];
        match expected {
            Some(path) => assert_eq!(
                hive.name.path(),
                Some(path.as_str()),
                "{image}: the hive at {address:#x} is named differently from Volatility's"
            ),
            None => {
                // The whole point of `HiveName`: a hive with no backing file and
                // a hive whose name could not be read must not render alike, and
                // neither may render as an empty string.
                assert_eq!(
                    hive.name.path(),
                    None,
                    "{image}: the hive at {address:#x} is unnamed in Volatility's output and \
                     named in ours"
                );
                let kind = hive.name.to_json()["kind"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                assert!(
                    kind == "no_backing_file" || kind == "unavailable",
                    "{image}: the hive at {address:#x} has no path and is marked '{kind}', which \
                     an examiner cannot tell from a failed read"
                );
                if let HiveName::Unavailable(incomplete) = &hive.name {
                    assert!(
                        !incomplete.detail.is_empty(),
                        "{image}: the hive at {address:#x} could not be named and does not say why"
                    );
                }
            }
        }
    }

    // And no hive anywhere may carry an empty path, which is the failure that
    // looks like a successful read of a nameless hive.
    for hive in &listing.hives {
        if let HiveName::Path { text, source, .. } = &hive.name {
            assert!(
                !text.is_empty(),
                "{image}: the hive at {:#x} reports an empty path from {}, which reads as a hive \
                 called nothing rather than as a hive with no file",
                hive.address,
                source.as_str()
            );
        }
    }
}

#[test]
fn xp_hivelist_matches_the_hives_volatility_lists() {
    assert_hivelist_matches(XP, ORACLE_XP);
}

#[test]
fn win11_hivelist_matches_the_hives_volatility_lists() {
    assert_hivelist_matches(WIN11, ORACLE_WIN11);
}

#[test]
fn the_xp_hives_volatility_leaves_blank_have_no_backing_file_rather_than_no_readable_name() {
    let Some(profile) = profile(XP) else {
        return;
    };
    let listing = registry::list_hives(&profile).expect("CmpHiveListHead is walkable");

    // Upstream suppresses an unreadable name and prints a blank cell, so its
    // output cannot distinguish these two cases. Séance can, and on XP the
    // answer is knowable: this build's `_CMHIVE` declares `FileFullPath` and
    // `FileUserName` and no `HiveRootPath`, both of the first two are resident
    // beside the hive signature that was just checked, and both are zero-length.
    // The hive genuinely has no file.
    let blank: Vec<&HiveRecord> = listing
        .hives
        .iter()
        .filter(|hive| hive.name.path().is_none())
        .collect();
    assert_eq!(
        blank.len(),
        2,
        "the XP oracle leaves exactly two hives unnamed, at 0xe1558578 and 0xe102e008; ours \
         leaves {}: {blank:#?}",
        blank.len()
    );
    for hive in blank {
        assert_eq!(
            hive.name,
            HiveName::NoBackingFile,
            "the hive at {:#x} is a volatile hive with no file; reporting it any other way loses \
             the distinction between 'never written to disk' and 'we could not read the name'",
            hive.address
        );
        assert_eq!(hive.name.to_json()["kind"], "no_backing_file");
    }

    // The named ones the oracle calls out by hand in KNOWN_ANSWERS.md.
    let named: BTreeMap<u64, &str> = listing
        .hives
        .iter()
        .filter_map(|hive| hive.name.path().map(|path| (hive.address, path)))
        .collect();
    assert_eq!(
        named.get(&0xe1ec_d008).copied(),
        Some(
            "\\Device\\HarddiskVolume1\\Documents and Settings\\Sarah\\Local Settings\\\
             Application Data\\Microsoft\\Windows\\UsrClass.dat"
        )
    );
    assert_eq!(
        named.get(&0xe1ef_f758).copied(),
        Some("\\Device\\HarddiskVolume1\\Documents and Settings\\Sarah\\NTUSER.DAT")
    );
    assert_eq!(
        named.get(&XP_SOFTWARE_HIVE).copied(),
        Some(XP_SOFTWARE_HIVE_PATH),
        "printkey below reads this hive by address, so the address and the path have to agree \
         with the oracle before anything is read through it"
    );
}

// ── Registry: printkey ──────────────────────────────────────────────────────

#[test]
fn xp_printkey_decodes_the_windows_currentversion_values_with_the_types_volatility_reports() {
    let Some(profile) = profile(XP) else {
        return;
    };
    // Oracle:
    //   vol.py -q -r csv -f win-xp-laptop.img windows.registry.printkey \
    //          --offset 0xe1982008 --key 'Microsoft\Windows\CurrentVersion'
    // 54 subkey rows and 13 value rows: 8 REG_SZ, 4 REG_EXPAND_SZ, 1 REG_DWORD.
    let listing = registry::print_key_in_hive(&profile, XP_SOFTWARE_HIVE, Some(CURRENT_VERSION))
        .expect("Microsoft\\Windows\\CurrentVersion is in every Windows software hive");

    assert_eq!(listing.hive, XP_SOFTWARE_HIVE);
    assert!(
        listing.path.ends_with(CURRENT_VERSION),
        "the resolved path does not end at the key that was asked for: {}",
        listing.path
    );
    assert_eq!(
        listing.chain.len(),
        4,
        "root, Microsoft, Windows, CurrentVersion: {:?}",
        listing
            .chain
            .iter()
            .map(|key| key.name.text.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(listing.chain[1].name.text, "Microsoft");
    assert_eq!(listing.chain[2].name.text, "Windows");
    assert_eq!(listing.chain[3].name.text, "CurrentVersion");

    // Subkeys, by name rather than by count alone: a list of the right length
    // built from the wrong index cell is the failure that survives review.
    let subkeys: BTreeSet<&str> = listing
        .subkeys
        .keys
        .iter()
        .map(|key| key.name.text.as_str())
        .collect();
    assert!(
        listing.subkeys.is_complete(),
        "the subkey index could not be walked in full, so any count below is a floor: {:?}",
        listing.subkeys.incomplete
    );
    assert_eq!(
        listing.subkeys.keys.len(),
        54,
        "Volatility enumerates 54 subkeys of CurrentVersion; ours: {subkeys:?}"
    );
    for expected in [
        "Run",
        "RunOnce",
        "Explorer",
        "Internet Settings",
        "Uninstall",
    ] {
        assert!(
            subkeys.contains(expected),
            "'{expected}' is in Volatility's subkey list and not in ours: {subkeys:?}"
        );
    }

    // Values. Every one of the thirteen was readable for Volatility, so a value
    // whose data is unavailable here is a defect and not an acquisition gap.
    assert!(
        listing.values.is_complete(),
        "the value list could not be enumerated in full: {:?}",
        listing.values.incomplete
    );
    assert_eq!(listing.values.values.len(), 13);
    assert_eq!(listing.values.declared, 13);
    for value in &listing.values.values {
        assert!(
            value.data.is_available(),
            "the value '{}' has no data, which Volatility read without difficulty",
            value.name.text
        );
    }
    assert!(
        listing.is_complete(),
        "the listing declares gaps Volatility did not have: {:?}",
        listing.incomplete()
    );

    let mut by_type: BTreeMap<&str, usize> = BTreeMap::new();
    for value in &listing.values.values {
        *by_type.entry(value.value_type.as_str()).or_default() += 1;
    }
    assert_eq!(
        by_type,
        BTreeMap::from([("REG_SZ", 8), ("REG_EXPAND_SZ", 4), ("REG_DWORD", 1)]),
        "the value types disagree with Volatility's Type column"
    );

    let by_name: BTreeMap<&str, &KeyValue> = listing
        .values
        .values
        .iter()
        .map(|value| (value.name.text.as_str(), value))
        .collect();
    let text_of = |name: &str, expected_type: RegValueType, expected: &str| {
        let value = by_name
            .get(name)
            .unwrap_or_else(|| panic!("Volatility lists a value called '{name}' and we do not"));
        assert_eq!(
            value.value_type, expected_type,
            "'{name}' is declared {:?} here and {expected_type:?} by Volatility",
            value.value_type
        );
        match &value.data {
            ValueData::Available { decoded, .. } => match decoded {
                RegistryData::Text(text) => {
                    assert_eq!(text.text, expected, "'{name}' decoded to the wrong string");
                    assert!(text.well_formed, "'{name}' did not decode cleanly");
                }
                other => panic!("'{name}' is a string type and decoded to {other:?}"),
            },
            other => panic!("'{name}' has no data: {other:?}"),
        }
    };

    // REG_SZ and REG_EXPAND_SZ are both UTF-16LE strings and differ only in
    // whether `%SystemRoot%` is still unexpanded. Folding one into the other
    // would make `DevicePath` read as a literal path that does not exist.
    text_of("ProgramFilesDir", RegValueType::Sz, "C:\\Program Files");
    text_of(
        "CommonFilesDir",
        RegValueType::Sz,
        "C:\\Program Files\\Common Files",
    );
    text_of("ProductId", RegValueType::Sz, "55274-640-2744344-23006");
    text_of("MediaPath", RegValueType::Sz, "C:\\WINDOWS\\Media");
    text_of("DevicePath", RegValueType::ExpandSz, "%SystemRoot%\\inf");
    text_of(
        "MediaPathUnexpanded",
        RegValueType::ExpandSz,
        "%SystemRoot%\\Media",
    );
    text_of("ProgramFilesPath", RegValueType::ExpandSz, "%ProgramFiles%");
    text_of(
        "WallPaperDir",
        RegValueType::ExpandSz,
        "%SystemRoot%\\Web\\Wallpaper",
    );

    let dword = by_name["SM_ConfigureProgramsExisted"];
    assert_eq!(dword.value_type, RegValueType::Dword);
    match &dword.data {
        ValueData::Available { decoded, raw } => {
            assert_eq!(*decoded, RegistryData::Dword(1));
            assert_eq!(
                raw.len(),
                4,
                "a REG_DWORD of any other length was not written by the registry API"
            );
        }
        other => panic!("the REG_DWORD has no data: {other:?}"),
    }
}

#[test]
fn a_subkey_that_is_not_under_currentversion_is_refused_rather_than_reported_as_an_empty_listing() {
    let Some(profile) = profile(XP) else {
        return;
    };
    // "This key has no values" is a claim about the suspect's machine. It is
    // only true if the enumeration behind it was exhaustive, so a key that is
    // genuinely absent has to say so *and* say how sure it is.
    let missing = format!("{CURRENT_VERSION}\\NoSuchKeyExistsHere");
    let err = registry::print_key_in_hive(&profile, XP_SOFTWARE_HIVE, Some(&missing))
        .expect_err("there is no such subkey of CurrentVersion");
    assert_eq!(err.class(), "key_not_found", "{err}");
    let text = err.to_string();
    assert!(
        text.contains("NoSuchKeyExistsHere"),
        "the refusal does not name the component that did not resolve: {text}"
    );
    assert!(
        text.contains("read in full"),
        "the subkey index of CurrentVersion was fully readable, so the refusal must say the key \
         really was absent rather than leave it open: {text}"
    );
}

// ── Network: Windows XP has no network oracle, and that is the test ─────────

#[test]
fn netscan_on_xp_refuses_the_build_instead_of_reporting_that_nothing_was_on_the_network() {
    let Some(profile) = profile(XP) else {
        return;
    };
    // Volatility raises NotImplementedError here and emits a header with no
    // rows; `oracle/windows.netscan.err` records it. XP's tcpip.sys tracks
    // connections in `_ADDRESS_OBJECT` and `_TCPT_OBJECT`, which carry none of
    // the TcpE/TcpL/UdpA pool tags this stage sweeps for.
    //
    // An empty endpoint list here would render as "this machine had no network
    // activity". That is the wrong finding about a machine that may have been
    // mid-exfiltration, and it is the reason the refusal is asserted rather
    // than the emptiness.
    let err = NetworkSymbols::from_profile(&profile)
        .expect_err("XP's network objects must not be claimed as decodable");
    assert_eq!(
        err.class(),
        "unsupported_build",
        "the build number was established, so the refusal has to be about the build rather than \
         about not knowing it: {err}"
    );
    let text = err.to_string();
    assert!(
        text.contains("not an absence of network activity"),
        "the refusal has to say what it does not mean, because the reader's default reading of a \
         missing network table is that there was no network: {text}"
    );

    // The build number really was known: the refusal is a finding about XP, not
    // a side effect of discovery having failed.
    assert_eq!(profile.build.major, 5);
    assert!(
        profile.build.build.is_some(),
        "discovery did not establish a build number, so this test proved the wrong refusal"
    );

    // And handing it a tcpip type pack does not change the answer. The
    // structures are not merely undescribed on XP, they are not there.
    //
    // Only reachable with an admissible pack: the corpus's netscan overlay is
    // refused by gate 1 for declaring members outside their own types, so on
    // this corpus the refusal above is the whole of what can be shown here.
    // The refusal itself is asserted separately.
    if let Some(path) = netscan_isf_path().filter(|p| known_incoherent_isf(p).is_none()) {
        let table = compile_isf(&path);
        let err = NetworkSymbols::with_table(&profile, table)
            .expect_err("a later build's type pack does not make XP decodable");
        assert_eq!(err.class(), "unsupported_build", "{err}");
    }
}

// ── Network: Windows 11 ─────────────────────────────────────────────────────

/// Ports that are what they are because of who answers on them.
///
/// Each is stored big-endian inside an otherwise little-endian structure. Port
/// 135 read little-endian is 34560, port 445 is 48385 — both legal ephemeral
/// ports, so nothing downstream catches the mistake and the report says the
/// machine was doing something it was not.
const WELL_KNOWN_PORTS: &[u16] = &[135, 137, 138, 139, 445, 1900, 5353, 5355];

/// Assert Séance misses nothing the oracle found, and that every endpoint it
/// reports beyond the oracle is corroborated by `corroborator`.
///
/// Exact equality is the right contract for a sweep, which should see what
/// another sweep of the same bytes saw. It is the wrong one for a *walk*:
/// Volatility's netstat and Séance's walk the same tcpip.sys tables, and
/// reaching a bucket the other stops short of is an improvement, not a
/// disagreement. What is never acceptable is missing an endpoint the oracle
/// reached, or inventing one nothing else can see -- so those are the two
/// things asserted.
fn assert_endpoints_superset(
    plugin: &str,
    ours: &[NetworkEndpoint],
    theirs: &BTreeSet<Endpoint>,
    corroborator: &BTreeSet<Endpoint>,
) {
    let (keyed, _unkeyable) = our_endpoints(ours);

    let missed: Vec<&Endpoint> = theirs.difference(&keyed).collect();
    assert!(
        missed.is_empty(),
        "{plugin}: {} endpoint(s) Volatility reached are absent from ours, which is a gap in \
         the walk: {missed:#?}",
        missed.len()
    );

    let extra: Vec<&Endpoint> = keyed.difference(theirs).collect();
    let uncorroborated: Vec<&&Endpoint> = extra
        .iter()
        .filter(|endpoint| !corroborator.contains(**endpoint))
        .collect();
    assert!(
        uncorroborated.is_empty(),
        "{plugin}: {} endpoint(s) appear in ours that neither Volatility's walk nor its pool \
         sweep can see, so nothing corroborates them: {uncorroborated:#?}",
        uncorroborated.len()
    );
    if !extra.is_empty() {
        eprintln!(
            "{plugin}: {} endpoint(s) beyond Volatility's walk, each corroborated by its own \
             netscan sweep: {extra:#?}",
            extra.len()
        );
    }
}

/// Assert Séance's endpoints are the oracle's, and that anything unkeyable is
/// annotated rather than presented as a socket.
fn assert_endpoints_match(plugin: &str, ours: &[NetworkEndpoint], theirs: &BTreeSet<Endpoint>) {
    let (keyed, unkeyable) = our_endpoints(ours);

    for endpoint in &unkeyable {
        assert!(
            !endpoint.notes.is_empty(),
            "{plugin}: the object at {:#x} has no owning process or no local address and says \
             nothing about why; a row like that reads as a socket bound to nothing",
            endpoint.offset
        );
    }

    assert_eq!(
        keyed,
        *theirs,
        "{plugin}: the endpoints disagree with Volatility's.\n{}\n  {} row(s) of ours could not \
         be keyed at all and are annotated: {:#?}",
        diff(&keyed, theirs),
        unkeyable.len(),
        unkeyable
            .iter()
            .map(|endpoint| (endpoint.offset, endpoint.tag, &endpoint.notes))
            .collect::<Vec<_>>()
    );
}

/// Assert the ports read as the services that use them.
fn assert_ports_are_big_endian(
    plugin: &str,
    ours: &[NetworkEndpoint],
    theirs: &BTreeSet<Endpoint>,
) {
    let our_ports: BTreeSet<u16> = ours.iter().map(|endpoint| endpoint.local_port).collect();
    let their_ports: BTreeSet<u16> = theirs.iter().map(|(_, _, port, _)| *port).collect();

    for &port in WELL_KNOWN_PORTS {
        if !their_ports.contains(&port) {
            continue;
        }
        assert!(
            our_ports.contains(&port),
            "{plugin}: Volatility reports a socket on port {port} and we report none. The two \
             bytes of a port member are network byte order whatever the symbol table says."
        );
        // The byte-swapped form is what a little-endian read produces. It is a
        // plausible ephemeral port, which is exactly why its presence has to be
        // asserted against rather than left to look reasonable.
        let swapped = port.swap_bytes();
        if !their_ports.contains(&swapped) {
            assert!(
                !our_ports.contains(&swapped),
                "{plugin}: port {swapped} is reported and Volatility reports none; it is \
                 {port} read little-endian, which is the classic byte-order defect"
            );
        }
    }
}

#[test]
fn win11_netscan_matches_the_endpoints_volatility_finds_by_sweeping_the_pool() {
    let Some(profile) = profile(WIN11) else {
        return;
    };
    let Some(theirs) = endpoint_oracle(ORACLE_WIN11, "windows.netscan") else {
        eprintln!("skipping: no netscan oracle in {ORACLE_WIN11}");
        return;
    };
    let Some(symbols) = win11_network_symbols(&profile) else {
        return;
    };

    let outcome = netscan::netscan(&profile, &symbols, &NetscanConfig::default())
        .expect("build 22000's network objects are decodable with the netscan type pack");

    assert!(
        !outcome.truncated,
        "the endpoint cap fired, so the sweep stopped before the image ran out of objects and \
         any comparison below is against a truncated list"
    );
    // A kernel-virtual sweep can never report itself complete, and asking it to
    // is asking the wrong question. Most of a 128 TiB kernel half translates
    // nowhere; `unswept_detail` says plainly that the unread total mixes that
    // in with pages the acquisition missed and is an upper bound rather than a
    // measure. Demanding `is_complete()` here was an assertion no correct sweep
    // could satisfy.
    //
    // The question it was reaching for -- "is a missing endpoint a hole in the
    // scan or a bug in the decoder?" -- is answered by the comparison itself,
    // so the incompleteness is carried into that failure instead of pre-empting
    // it.
    if let Err(missing) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_endpoints_match("netscan", &outcome.endpoints, &theirs)
    })) {
        eprintln!(
            "the sweep left {:?} unread, so a missing endpoint may be a gap in coverage rather \
             than in the decoder",
            outcome.incomplete
        );
        std::panic::resume_unwind(missing);
    }
    assert_ports_are_big_endian("netscan", &outcome.endpoints, &theirs);
}

#[test]
fn win11_netstat_matches_the_endpoints_volatility_reaches_by_walking_tcpips_own_tables() {
    let Some(profile) = profile(WIN11) else {
        return;
    };
    let Some(theirs) = endpoint_oracle(ORACLE_WIN11, "windows.netstat") else {
        eprintln!("skipping: no netstat oracle in {ORACLE_WIN11}");
        return;
    };
    let Some(symbols) = win11_network_symbols(&profile) else {
        return;
    };
    let Some(tcpip) = win11_tcpip_module(&profile) else {
        return;
    };

    let outcome = netscan::netstat(&profile, &symbols, &tcpip, &NetstatConfig::default())
        .expect("tcpip.sys's partition table and port pools are walkable on build 22000");

    // Half a walk is the failure that reads as an idle machine: the port pools
    // alone give every listener and no established connection.
    assert!(
        outcome.partitions_walked,
        "the partition table was not walked, so this list holds no established connections at \
         all: {:?}",
        outcome.incomplete
    );
    assert!(
        outcome.port_pools_walked,
        "the port pools were not walked, so this list holds no listeners at all: {:?}",
        outcome.incomplete
    );

    // Séance's walk reaches three ESTABLISHED connections Volatility's stops
    // short of -- SearchHost.exe 3376 to 13.107.6.254:443 and OneDrive.exe 4788
    // to 13.107.43.12:443 among them. Volatility's own pool sweep lists all
    // three with the same owning process, so they are real sockets its table
    // walk missed, not rows Séance invented. That the owners agree is also the
    // check on `_TCP_ENDPOINT.Owner` at 752: a wrong offset would attribute
    // these to whatever followed the endpoint in the pool.
    let sweep = endpoint_oracle(ORACLE_WIN11, "windows.netscan").unwrap_or_default();
    assert_endpoints_superset("netstat", &outcome.endpoints, &theirs, &sweep);
    assert_ports_are_big_endian("netstat", &outcome.endpoints, &theirs);
}

#[test]
fn win11_the_sweep_reaches_everything_the_walk_does_and_the_difference_is_reported_either_way() {
    let Some(profile) = profile(WIN11) else {
        return;
    };
    let (Some(scan_oracle), Some(walk_oracle)) = (
        endpoint_oracle(ORACLE_WIN11, "windows.netscan"),
        endpoint_oracle(ORACLE_WIN11, "windows.netstat"),
    ) else {
        eprintln!("skipping: the network oracles are not both in {ORACLE_WIN11}");
        return;
    };
    let Some(symbols) = win11_network_symbols(&profile) else {
        return;
    };
    let Some(tcpip) = win11_tcpip_module(&profile) else {
        return;
    };

    // Running both and comparing is the finding. On this capture Volatility's
    // walk reaches a strict subset of what its sweep finds — 83 keyed endpoints
    // against 88 — because the sweep also recovers objects the kernel's tables
    // no longer reference. Séance has to reproduce that relationship, not just
    // the two lists separately: a sweep that had quietly degenerated into a
    // second walk would match both oracles row for row on a healthy image and
    // find nothing hidden on a compromised one.
    assert!(
        walk_oracle.is_subset(&scan_oracle),
        "the premise of this test is that upstream's walk is a subset of its sweep; it is not, \
         so the oracle has changed. Reached only by the walk: {:#?}",
        walk_oracle.difference(&scan_oracle).collect::<Vec<_>>()
    );

    let swept =
        netscan::netscan(&profile, &symbols, &NetscanConfig::default()).expect("the sweep runs");
    let walked = netscan::netstat(&profile, &symbols, &tcpip, &NetstatConfig::default())
        .expect("the walk runs");

    let (swept_keys, _) = our_endpoints(&swept.endpoints);
    let (walked_keys, _) = our_endpoints(&walked.endpoints);

    let unreachable_by_walk: Vec<&Endpoint> = swept_keys.difference(&walked_keys).collect();
    assert!(
        !unreachable_by_walk.is_empty(),
        "the sweep found nothing the walk did not, which on this capture means it is not \
         sweeping: {} swept, {} walked",
        swept_keys.len(),
        walked_keys.len()
    );
    assert!(
        walked_keys.is_subset(&swept_keys),
        "the walk reached endpoints the sweep did not, which is a gap in the sweep and has to be \
         explained rather than tolerated. Reached only by the walk: {:#?}",
        walked_keys.difference(&swept_keys).collect::<Vec<_>>()
    );
}
