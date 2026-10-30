#![no_main]

//! Fuzz the version 14, 15 and 23 PST/OST layers: the 512-byte B-tree page
//! walk, the 64-byte-aligned block scan, the extended-block and subnode trees,
//! the permutative decoding, and the deleted-message recovery over them
//! (`pst512`), through `parse_pst`, the path a real file takes.
//!
//! Every page and block is signature- and CRC-gated, so a mutated one is
//! refused at the gate and nothing above it is reached. Before the entry
//! points run, this target re-seals what the mutator broke: every 64-byte
//! boundary whose trailer carries a plausible size has its block signature and
//! CRC recomputed, then every 512-byte slot whose trailer names a B-tree page
//! type has its signature and CRC recomputed (last, so it covers any bytes the
//! block pass touched). The first byte picks the
//! layout (ANSI 14 or 15, Unicode 23) and the encryption method, and the store
//! is given a valid header identity; the roots are the seed's own, so mutation reaches the page metadata, the entry lists, the
//! extended-block and subnode readers and the heap above them.
//!
//! Seed with the fixtures in `seance_plugin_email/tests/fixtures/pst_old/`.
//!
//! Goal: no panic, no unbounded allocation, no hang.

use libfuzzer_sys::fuzz_target;
use seance_plugin_email::ost4k::crc::{ndb_crc, ndb_sig};

const PAGE: usize = 512;
const SLOT: usize = 64;

fn le32(d: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]])
}

fn le64(d: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(d[i..i + 8].try_into().unwrap())
}

/// Recompute the gates the mutator broke. `unicode` picks the trailer shape:
/// 16 bytes with the CRC before a 64-bit id, or 12 with a 32-bit id first.
///
/// The block pass runs first and the page pass last: a 64-byte boundary inside
/// a B-tree page is entry data that can read as a block trailer, and sealing
/// it after the page was sealed would leave the page CRC stale.
fn reseal(store: &mut [u8], unicode: bool) {
    let tl = if unicode { 16 } else { 12 };
    let mut end = SLOT;
    while end <= store.len() {
        let t = end - tl;
        let cb = usize::from(u16::from_le_bytes([store[t], store[t + 1]]));
        let slot = (cb + tl).div_ceil(SLOT) * SLOT;
        if cb != 0 && cb <= 8192 - tl && slot <= end {
            let start = end - slot;
            let bid = if unicode {
                le64(store, t + 8)
            } else {
                u64::from(le32(store, t + 4))
            };
            store[t + 2..t + 4].copy_from_slice(&ndb_sig(start as u64, bid).to_le_bytes());
            let crc = ndb_crc(&store[start..start + cb]).to_le_bytes();
            let at = if unicode { t + 4 } else { t + 8 };
            store[at..at + 4].copy_from_slice(&crc);
        }
        end += SLOT;
    }
    let mut ib = 0;
    while ib + PAGE <= store.len() {
        let t = ib + PAGE - tl;
        let pt = store[t];
        if (pt == 0x80 || pt == 0x81) && store[t + 1] == pt {
            let bid = if unicode {
                le64(store, t + 8)
            } else {
                u64::from(le32(store, t + 4))
            };
            store[t + 2..t + 4].copy_from_slice(&ndb_sig(ib as u64, bid).to_le_bytes());
            let crc = ndb_crc(&store[ib..t]).to_le_bytes();
            let at = if unicode { t + 4 } else { t + 8 };
            store[at..at + 4].copy_from_slice(&crc);
        }
        ib += PAGE;
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 1024 || data.len() > 4 * 1024 * 1024 {
        return;
    }
    let (kind, rest) = (data[0], &data[1..]);
    let (version, unicode, crypt_at) = match kind % 3 {
        0 => (14u16, false, 461usize),
        1 => (15, false, 461),
        _ => (23, true, 513),
    };
    let mut store = rest.to_vec();
    store[..4].copy_from_slice(b"!BDN");
    store[10..12].copy_from_slice(&version.to_le_bytes());
    store[crypt_at] = (kind >> 2) % 3;
    reseal(&mut store, unicode);
    let _ = seance_plugin_email::pst512::recover(&store);
    let _ =
        seance_plugin_email::parse_pst(&store, uuid::Uuid::nil(), uuid::Uuid::nil(), "fuzz.pst");
});
