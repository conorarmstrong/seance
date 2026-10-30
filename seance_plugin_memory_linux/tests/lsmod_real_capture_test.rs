//! The kernel-module stage against real Linux captures (`MEM-042`).
//!
//! Both lab guests (`SEANCE_LINUX_SWAP_MEM`: Ubuntu 22.04 / 5.15;
//! `SEANCE_LINUX_NOBLE_MEM`: Ubuntu 24.04 / 6.8) are profiled from the image
//! alone — BTF and kallsyms recovered from the capture, no symbol file.
//!
//! What is graded, and against what:
//!
//! * **`autofs4` is listed.** The guests' own serial consoles, written during
//!   the boot that was captured, record `systemd[1]: Inserted module
//!   'autofs4'` (`serial.log` in each lab directory). That is the one
//!   module-load the ground truth records by name; no `lsmod` listing was taken
//!   inside either guest before acquisition, so the rest of the list is not
//!   graded for completeness here.
//! * **Every module's state is named `MODULE_STATE_LIVE`.** The name comes from
//!   the `module_state` enumeration recovered from the image's BTF; before
//!   `MEM-042` an image-derived table carried no enumerations and every
//!   `state_name` was `None`. `LIVE` is 0 in `include/linux/module.h`, and a
//!   guest idling at its login prompt has no module mid-load or mid-unload.
//! * **On 6.8, `module.mem[]` is decoded by this stage.** The size columns
//!   were absent with a note saying so; they are now read from the array,
//!   indexed by the `mod_mem_type` constants the table carries, and the text
//!   extent is `mem[MOD_TEXT]` — which must not contain the `struct module`
//!   itself (it lives in the module's data), the same geometric check the hook
//!   stage's code map is held to.

use seance_core::data_source::{DataSource, FileDataSource};
use seance_memory::binding::Field;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_linux::discovery::{self, DiscoveryOptions};
use seance_plugin_memory_linux::lsmod;
use seance_plugin_memory_linux::profile::LinuxProfile;
use std::path::PathBuf;
use std::sync::Arc;

fn profiled(var: &str) -> Option<LinuxProfile> {
    let d = PathBuf::from(std::env::var(var).ok()?);
    if !d.is_dir() {
        return None;
    }
    let src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(d.join("mem.raw")).expect("open mem.raw"));
    let physical: Arc<dyn MemoryLayer> =
        Arc::new(PhysicalLayer::raw(src).expect("raw is a physical layer"));
    Some(
        discovery::discover(physical, &[], &DiscoveryOptions::default())
            .expect("the capture is present and profiles"),
    )
}

fn modules_of(profile: &LinuxProfile) -> lsmod::ModuleList {
    let layout = lsmod::bind(profile).expect("the module layout binds");
    lsmod::list_modules(profile, &layout, &lsmod::ModuleListConfig::default())
        .expect("the module list walks")
}

fn assert_named_live_and_autofs4(kernel: &str, list: &lsmod::ModuleList) {
    assert!(list.stop.is_complete(), "{kernel}: {}", list.stop.as_str());
    let names: Vec<String> = list
        .modules
        .iter()
        .filter_map(|m| m.name.known().cloned())
        .collect();
    eprintln!("{kernel}: {} modules: {names:?}", names.len());
    assert!(
        names.iter().any(|n| n == "autofs4"),
        "{kernel}: the guest's serial console records systemd inserting autofs4, and the \
         list does not have it: {names:?}"
    );
    for module in &list.modules {
        assert_eq!(
            module.state,
            Field::Known(0),
            "{kernel}: {:?} is not in state 0",
            module.name
        );
        assert_eq!(
            module.state_name.as_deref(),
            Some("MODULE_STATE_LIVE"),
            "{kernel}: {:?}'s state was not named from the image's module_state enumeration",
            module.name
        );
    }
}

#[test]
fn a_5_15_guest_lists_autofs4_and_names_every_state() {
    let Some(profile) = profiled("SEANCE_LINUX_SWAP_MEM") else {
        eprintln!("skipping: set SEANCE_LINUX_SWAP_MEM to the 5.15 capture dir");
        return;
    };
    let list = modules_of(&profile);
    assert_named_live_and_autofs4("5.15", &list);
    // 5.15 has core_layout; there is no mem[] to decode.
    for module in &list.modules {
        assert!(module.memory.is_empty(), "{:?}", module.name);
        assert!(
            matches!(module.core_size, Field::Known(size) if size > 0),
            "{:?}: {:?}",
            module.name,
            module.core_size
        );
    }
}

#[test]
fn a_6_8_guest_decodes_module_mem_into_the_size_columns() {
    let Some(profile) = profiled("SEANCE_LINUX_NOBLE_MEM") else {
        eprintln!("skipping: set SEANCE_LINUX_NOBLE_MEM to the 6.8 capture dir");
        return;
    };
    let list = modules_of(&profile);
    assert_named_live_and_autofs4("6.8", &list);

    for module in &list.modules {
        let name = module.name.known().cloned().unwrap_or_default();
        assert!(
            module.notes.iter().all(|n| !n.contains("does not decode")),
            "{name}: the mem[] note is still published: {:?}",
            module.notes
        );
        let text = module
            .memory
            .iter()
            .find(|r| r.kind == "MOD_TEXT")
            .unwrap_or_else(|| panic!("{name}: no MOD_TEXT region among {:?}", module.memory));
        assert!(text.base != 0 && text.size > 0, "{name}: {text:?}");
        assert_eq!(module.core_base, Field::Known(text.base), "{name}");
        // The struct module is data; it cannot lie in the text extent.
        assert!(
            !(module.address >= text.base && module.address < text.base + text.size),
            "{name}: struct module at {:#x} lies in what was read as mem[MOD_TEXT] \
             ({:#x}+{:#x}), so the index is wrong",
            module.address,
            text.base,
            text.size
        );
        // Core is text + data + rodata + ro_after_init, each read.
        let core: u64 = module
            .memory
            .iter()
            .filter(|r| !r.kind.starts_with("MOD_INIT_"))
            .map(|r| r.size)
            .sum();
        assert_eq!(module.core_size, Field::Known(core as i64), "{name}");
        assert!(
            matches!(module.init_size, Field::Known(_)),
            "{name}: {:?}",
            module.init_size
        );
        assert!(
            matches!(module.code_size, Field::Known(size) if size >= core as i64),
            "{name}: {:?}",
            module.code_size
        );
        assert!(module.unreadable_fields().is_empty(), "{name}");
    }
    let json = list.to_json();
    if let Some(autofs4) = json["modules"].as_array().and_then(|m| {
        m.iter()
            .find(|m| m["name"].to_string().contains("\"autofs4\""))
    }) {
        eprintln!("6.8 autofs4: {autofs4}");
    }
    assert!(
        json["modules"][0]["memory"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "{}",
        json["modules"][0]
    );
}
