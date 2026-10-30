#![no_main]

//! Fuzz the Outlook 2013+ OST reader (format version 36): the 4 KiB B-tree
//! page walk, the block reader with its zlib inflation, the XBLOCK/SLBLOCK
//! trees, the heap-on-node / BTH / property-context layer, and the folder and
//! message walk above them, and the deleted-message recovery that re-walks
//! the bytes with the allocation map ignored (`ost4k::recover`).
//!
//! Every B-tree page and every block is CRC-gated, so a mutated page or block
//! would be refused at its CRC and the layers above it reached only by the
//! unmutated seed. So before either entry point runs, the target re-seals
//! what the mutator broke: every page reachable from the two roots gets its
//! BID, signature and CRC recomputed, and every block
//! the (re-sealed) block B-tree names gets its trailer — cb, signature, CRC,
//! BID, inflated size — rewritten to match the entry. Mutations then reach
//! the page metadata, the XBLOCK/XXBLOCK and SLBLOCK/SIBLOCK trees, the
//! heap-on-node, BTH and property-context readers, and the zlib inflate.
//!
//! Two entry points per input:
//!
//! * The first 32 bytes name the two B-tree roots (bid, ib, the offset
//!   rounded down to a page) directly and the rest is the store, so random
//!   bytes reach the page and block readers without having to forge the
//!   header's two CRCs (`Ndb::from_roots`).
//! * The input is also given a valid version-36 header — magic, version and
//!   both CRCs recomputed over the fuzzed bytes — and handed to `parse_pst`,
//!   the path a real file takes.
//!
//! Seed with the Data Leakage fixture's referenced extent
//! (`fuzz/gen_seeds.py` cuts it from
//! `seance_plugin_email/tests/fixtures/ost_v36/`).
//!
//! Goal: no panic, no unbounded allocation, no hang.

use libfuzzer_sys::fuzz_target;
use seance_plugin_email::ost4k::{
    block::BLOCK_TRAILER,
    crc::{ndb_crc, ndb_sig},
    mailbox::read_mailbox,
    ndb::Ndb,
    recover::recover,
    Bref,
};

const PAGE: usize = 4096;
const TRAILER_AT: usize = 4072;

/// Re-seal every page reachable from the two roots (walked here the way the
/// reader walks them, so a unit that only looks like a page is never
/// touched), then every block the re-sealed block B-tree names.
fn reseal(store: &mut [u8], nbt_root: Bref, bbt_root: Bref) {
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![(nbt_root, 0usize), (bbt_root, 0)];
    while let Some((bref, depth)) = stack.pop() {
        let Ok(at) = usize::try_from(bref.ib) else {
            continue;
        };
        // `at` comes from fuzzed page bytes: a page-aligned value near
        // usize::MAX must not overflow here and pass off the harness's own
        // panic as the reader's.
        let in_bounds = at.checked_add(PAGE).is_some_and(|end| end <= store.len());
        if depth > 8 || at % PAGE != 0 || !in_bounds || !seen.insert(at) {
            continue;
        }
        let t = at + TRAILER_AT;
        store[t + 2..t + 4].copy_from_slice(&ndb_sig(bref.ib, bref.bid).to_le_bytes());
        store[t + 8..t + 16].copy_from_slice(&bref.bid.to_le_bytes());
        let crc = ndb_crc(&store[at..t]);
        store[t + 4..t + 8].copy_from_slice(&crc.to_le_bytes());
        // Intermediate pages (cLevel > 0) hold 24-byte (key, bid, ib) entries.
        let (c_ent, level) = (
            usize::from(u16::from_le_bytes([store[at + 4056], store[at + 4057]])),
            store[at + 4061],
        );
        if level > 0 {
            for i in 0..c_ent.min(4056 / 24) {
                let e = at + i * 24;
                stack.push((
                    Bref {
                        bid: le(store, e + 8),
                        ib: le(store, e + 16),
                    },
                    depth + 1,
                ));
            }
        }
    }
    let entries = Ndb::from_roots(store, nbt_root, bbt_root)
        .bbt
        .entries
        .clone();
    for e in entries {
        let cb = usize::from(e.cb);
        let slot = (cb + BLOCK_TRAILER).div_ceil(512) * 512;
        let Some(start) = usize::try_from(e.bref.ib).ok() else {
            continue;
        };
        let Some(end) = start.checked_add(slot).filter(|&end| end <= store.len()) else {
            continue;
        };
        let t = end - BLOCK_TRAILER;
        let crc = ndb_crc(&store[start..start + cb]);
        store[t..t + 2].copy_from_slice(&e.cb.to_le_bytes());
        store[t + 2..t + 4].copy_from_slice(&ndb_sig(e.bref.ib, e.bref.bid).to_le_bytes());
        store[t + 4..t + 8].copy_from_slice(&crc.to_le_bytes());
        store[t + 8..t + 16].copy_from_slice(&e.bref.bid.to_le_bytes());
        store[t + 18..t + 20].copy_from_slice(&e.cb_inflated.to_le_bytes());
    }
}

fn le(d: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(d[i..i + 8].try_into().unwrap())
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 || data.len() > 4 * 1024 * 1024 {
        return;
    }
    let len = data.len() as u64;
    let page = |ib: u64| (ib % len) & !(PAGE as u64 - 1);
    let nbt = Bref {
        bid: le(data, 0),
        ib: page(le(data, 8)),
    };
    let bbt = Bref {
        bid: le(data, 16),
        ib: page(le(data, 24)),
    };
    let mut sealed = data.to_vec();
    reseal(&mut sealed, nbt, bbt);
    let ndb = Ndb::from_roots(&sealed, nbt, bbt);
    for e in &ndb.bbt.entries {
        let _ = seance_plugin_email::ost4k::block::read_block(&sealed, e);
    }
    let mb = read_mailbox(&ndb);
    let _ = recover(&ndb, &mb);

    if data.len() >= 528 {
        let mut store = data.to_vec();
        store[..4].copy_from_slice(b"!BDN");
        store[10..12].copy_from_slice(&36u16.to_le_bytes());
        store[0x201] = 0;
        // The header's roots (NBT BREF at 0xD8, BBT BREF at 0xE8), as the
        // reader will take them, so the re-seal walks the same trees.
        if store.len() >= 0xF8 {
            let nbt = Bref {
                bid: le(&store, 0xD8),
                ib: le(&store, 0xE0),
            };
            let bbt = Bref {
                bid: le(&store, 0xE8),
                ib: le(&store, 0xF0),
            };
            reseal(&mut store, nbt, bbt);
        }
        let partial = ndb_crc(&store[8..8 + 471]);
        store[4..8].copy_from_slice(&partial.to_le_bytes());
        let full = ndb_crc(&store[8..8 + 516]);
        store[524..528].copy_from_slice(&full.to_le_bytes());
        let _ = seance_plugin_email::parse_pst(
            &store,
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            "fuzz.ost",
        );
    }
});
