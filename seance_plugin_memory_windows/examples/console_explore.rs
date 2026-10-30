//! Scratch exploration for the console-host derivation (S8-5.3). Not shipped.
use std::path::PathBuf;
use std::sync::Arc;

use seance_core::data_source::{DataSource, FileDataSource};
use seance_memory::translate::TableCache;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_windows::automagic::{self, DiscoveryOptions};
use seance_plugin_memory_windows::process::{
    list_processes, process_address_space, ProcessListConfig, ProcessSymbols,
};
use seance_plugin_memory_windows::vad::{list_vads, VadSymbols, VadWalkConfig};

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = PathBuf::from(&args[1]);
    let dump_mode = args[2] == "dump";
    let needle = if dump_mode {
        vec![]
    } else if let Some(h) = args[2].strip_prefix("p:") {
        u64::from_str_radix(h, 16).unwrap().to_le_bytes().to_vec()
    } else {
        utf16(&args[2])
    };
    let dirs = vec![
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../test_data/win11_bitlocker/symbols"
        )),
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../reference/volatility3/volatility3/symbols"
        )),
    ];
    let source: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).unwrap());
    let physical: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(source).unwrap());
    let profile = automagic::discover(physical, &dirs, &DiscoveryOptions::default()).unwrap();
    let ps = ProcessSymbols::from_profile(&profile).unwrap();
    let list = list_processes(&profile, &ps, &ProcessListConfig::default()).unwrap();
    let cache = Arc::new(TableCache::new());
    let vs = VadSymbols::from_profile(&profile).unwrap();
    for p in &list.processes {
        let name = p.image_file_name.known().cloned().unwrap_or_default();
        let pid = p.pid.known().copied().unwrap_or(0);
        let ppid = p.ppid.known().copied().unwrap_or(0);
        let want = args
            .get(3)
            .map(|s| s.split(',').any(|w| w == name || w == pid.to_string()))
            .unwrap_or(false);
        if name.contains("conhost")
            || name.contains("cmd")
            || name.contains("Console")
            || name.contains("Terminal")
        {
            println!(
                "PROC {name} pid {pid} ppid {ppid} eprocess {:#x} peb {:?}",
                p.address,
                p.peb.known()
            );
        }
        if !want {
            continue;
        }
        if dump_mode {
            let layer = process_address_space(&profile, &ps, p.address, &cache).unwrap();
            let va = u64::from_str_radix(args[4].trim_start_matches("0x"), 16).unwrap();
            let len: usize = args[5].parse().unwrap();
            let mut buf = vec![0u8; len];
            for i in (0..len).step_by(16) {
                let n = 16.min(len - i);
                let ok = layer
                    .read_at(va + i as u64, &mut buf[i..i + n])
                    .map(|r| r == n)
                    .unwrap_or(false);
                let row = &buf[i..i + n];
                if !ok {
                    println!("{:#x}  <unreadable>", va + i as u64);
                    continue;
                }
                let asc: String = row
                    .iter()
                    .map(|b| {
                        if (32..127).contains(b) {
                            *b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                let hex: Vec<String> = row.iter().map(|b| format!("{b:02x}")).collect();
                println!("{:#x}  {}  {}", va + i as u64, hex.join(" "), asc);
            }
            continue;
        }
        let layer = match process_address_space(&profile, &ps, p.address, &cache) {
            Ok(l) => l,
            Err(e) => {
                println!("  no space: {e}");
                continue;
            }
        };
        let tree = match list_vads(&profile, &vs, p.address, &VadWalkConfig::default()) {
            Ok(t) => t,
            Err(e) => {
                println!("  no vads: {e}");
                continue;
            }
        };
        for v in &tree.vads {
            if v.size() > (1 << 30) {
                continue;
            }
            let mut a = v.start;
            let mut buf = vec![0u8; 4096 * 16];
            while a <= v.end {
                let len = ((v.end - a + 1).min(buf.len() as u64)) as usize;
                // page at a time so a hole does not lose the run
                let mut off = 0;
                while off < len {
                    let n = (len - off).min(4096);
                    let ok = layer
                        .read_at(a + off as u64, &mut buf[off..off + n])
                        .map(|r| r == n)
                        .unwrap_or(false);
                    if !ok {
                        for b in &mut buf[off..off + n] {
                            *b = 0;
                        }
                    }
                    off += n;
                }
                let hay = &buf[..len];
                let mut i = 0;
                while let Some(pos) = memchr::memmem::find(&hay[i..], &needle) {
                    let va = a + (i + pos) as u64;
                    println!(
                        "HIT pid {pid} {name} va {va:#x} in vad {:#x}-{:#x} {:?} file {:?}",
                        v.start,
                        v.end,
                        v.protection_names,
                        v.file.to_json()
                    );
                    i += pos + 1;
                }
                a += len as u64;
            }
        }
    }
}
