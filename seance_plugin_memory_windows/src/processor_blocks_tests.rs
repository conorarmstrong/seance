//! The processor control regions: one record per processor the
//! `KiProcessorBlock` array names, each cross-checked against what the
//! structure says about itself.

use super::processor_blocks::*;
use crate::image_fixture::{Image, BASE_TYPES_X64};
use crate::poolscan::test_support::{profile, table};
use seance_memory::Architecture;

// Where the fixture puts things. Symbol addresses are RVAs off a kernel base of
// zero, so a symbol's address is also where the fixture writes it.
const KI_PROCESSOR_BLOCK: u64 = 0x100;
const KE_NUMBER_PROCESSORS: u64 = 0x200;
const KPCR_0: u64 = 0x1_0000;
const KPCR_1: u64 = 0x2_0000;
const KPCR_2: u64 = 0x3_0000;
const THREAD_0: u64 = 0x8_0000;
const PROCESS_0: u64 = 0x9_0000;

// `_KPCR` offsets the fixture declares.
const PCR_SELF: u64 = 0x18;
const PCR_CURRENT_PRCB: u64 = 0x20;
const PCR_KD_VERSION_BLOCK: u64 = 0x108;
const PCR_PRCB: u64 = 0x180;

// `_KPRCB` offsets.
const PRCB_CURRENT_THREAD: u64 = 0x8;
const PRCB_NEXT_THREAD: u64 = 0x10;
const PRCB_IDLE_THREAD: u64 = 0x18;
const PRCB_NUMBER: u64 = 0x24;
const PRCB_CPU_TYPE: u64 = 0x40;
const PRCB_MINOR_VERSION: u64 = 0x88;
const PRCB_MAJOR_VERSION: u64 = 0x8a;
const PRCB_CORES: u64 = 0xa0;
const PRCB_LOGICAL: u64 = 0xa4;

// `_KTHREAD` / `_EPROCESS`.
const KT_PROCESS: u64 = 0x220;
const EP_PID: u64 = 0x1d0;
const EP_NAME: u64 = 0x338;

fn isf(declares_number: bool) -> String {
    let number = if declares_number {
        format!(
            r#","Number": {{"offset": {PRCB_NUMBER}, "type": {{"kind": "base", "name": "unsigned long"}}}}"#
        )
    } else {
        String::new()
    };
    format!(
        r#"{{
  "metadata": {{
    "format": "6.2.0",
    "producer": {{"name": "seance-test", "version": "1.0.0"}},
    "windows": {{"pdb": {{"GUID": "1A1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 34404}}}}
  }},
  "base_types": {base},
  "user_types": {{
    "_KPRCB": {{"size": 512, "kind": "struct", "fields": {{
      "CurrentThread": {{"offset": {PRCB_CURRENT_THREAD}, "type": {{"kind": "pointer",
                        "subtype": {{"kind": "struct", "name": "_KTHREAD"}}}}}},
      "NextThread": {{"offset": {PRCB_NEXT_THREAD}, "type": {{"kind": "pointer",
                     "subtype": {{"kind": "struct", "name": "_KTHREAD"}}}}}},
      "IdleThread": {{"offset": {PRCB_IDLE_THREAD}, "type": {{"kind": "pointer",
                     "subtype": {{"kind": "struct", "name": "_KTHREAD"}}}}}},
      "CpuType": {{"offset": {PRCB_CPU_TYPE}, "type": {{"kind": "base", "name": "unsigned char"}}}},
      "MinorVersion": {{"offset": {PRCB_MINOR_VERSION}, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "MajorVersion": {{"offset": {PRCB_MAJOR_VERSION}, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "CoresPerPhysicalProcessor": {{"offset": {PRCB_CORES}, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "LogicalProcessorsPerCore": {{"offset": {PRCB_LOGICAL}, "type": {{"kind": "base", "name": "unsigned long"}}}}{number}
    }}}},
    "_KPCR": {{"size": 1024, "kind": "struct", "fields": {{
      "Self": {{"offset": {PCR_SELF}, "type": {{"kind": "pointer",
               "subtype": {{"kind": "struct", "name": "_KPCR"}}}}}},
      "CurrentPrcb": {{"offset": {PCR_CURRENT_PRCB}, "type": {{"kind": "pointer",
                      "subtype": {{"kind": "struct", "name": "_KPRCB"}}}}}},
      "KdVersionBlock": {{"offset": {PCR_KD_VERSION_BLOCK}, "type": {{"kind": "pointer",
                         "subtype": {{"kind": "base", "name": "void"}}}}}},
      "Prcb": {{"offset": {PCR_PRCB}, "type": {{"kind": "struct", "name": "_KPRCB"}}}}
    }}}},
    "_KTHREAD": {{"size": 1024, "kind": "struct", "fields": {{
      "Process": {{"offset": {KT_PROCESS}, "type": {{"kind": "pointer",
                  "subtype": {{"kind": "struct", "name": "_KPROCESS"}}}}}}
    }}}},
    "_KPROCESS": {{"size": 64, "kind": "struct", "fields": {{
      "Header": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned long"}}}}
    }}}},
    "_EPROCESS": {{"size": 1024, "kind": "struct", "fields": {{
      "Pcb": {{"offset": 0, "type": {{"kind": "struct", "name": "_KPROCESS"}}}},
      "UniqueProcessId": {{"offset": {EP_PID}, "type": {{"kind": "pointer",
                          "subtype": {{"kind": "base", "name": "void"}}}}}},
      "ImageFileName": {{"offset": {EP_NAME}, "type": {{"kind": "array", "count": 15,
                        "subtype": {{"kind": "base", "name": "unsigned char"}}}}}}
    }}}}
  }},
  "enums": {{}},
  "symbols": {{
    "KiProcessorBlock": {{"address": {KI_PROCESSOR_BLOCK}}},
    "KeNumberProcessors": {{"address": {KE_NUMBER_PROCESSORS}}}
  }}
}}"#,
        base = BASE_TYPES_X64,
    )
}

/// One processor's control region, written whole: the array slot, the
/// structure's self pointers and its own number.
fn write_processor(img: &mut Image, index: u64, kpcr: u64, number: u32, coherent: bool) {
    let prcb = kpcr + PCR_PRCB;
    img.put_u64(KI_PROCESSOR_BLOCK + index * 8, prcb);
    img.put_u64(kpcr + PCR_SELF, if coherent { kpcr } else { kpcr + 0x10 });
    img.put_u64(kpcr + PCR_CURRENT_PRCB, prcb);
    img.put_u32(prcb + PRCB_NUMBER, number);
    img.put_u16(prcb + PRCB_MAJOR_VERSION, 1);
    img.put_u16(prcb + PRCB_MINOR_VERSION, 1);
    img.put_u8(prcb + PRCB_CPU_TYPE, 6);
    img.put_u32(prcb + PRCB_CORES, 1);
    img.put_u32(prcb + PRCB_LOGICAL, 1);
    img.put_u64(prcb + PRCB_IDLE_THREAD, THREAD_0 + 0x1000 * index);
}

fn image(claimed: u32, processors: &[(u64, bool)]) -> Image {
    let mut img = Image::sized(0xA_0000);
    img.put_u32(KE_NUMBER_PROCESSORS, claimed);
    for (index, (kpcr, coherent)) in processors.iter().enumerate() {
        write_processor(&mut img, index as u64, *kpcr, index as u32, *coherent);
    }
    // Processor 0 is running a thread whose process is `svchost.exe`, pid 900.
    let prcb0 = KPCR_0 + PCR_PRCB;
    img.put_u64(prcb0 + PRCB_CURRENT_THREAD, THREAD_0);
    img.put_u64(THREAD_0 + KT_PROCESS, PROCESS_0);
    img.put_u64(PROCESS_0 + EP_PID, 900);
    img.write(PROCESS_0 + EP_NAME, b"svchost.exe\0");
    img
}

fn survey(claimed: u32, processors: &[(u64, bool)], declares_number: bool) -> ProcessorSurvey {
    let text = isf(declares_number);
    let profile = profile(
        image(claimed, processors).layer(),
        table(&text),
        Architecture::X64,
        10,
        0,
        Some(26200),
    );
    let symbols = ProcessorSymbols::from_profile(&profile).expect("this build declares the KPCR");
    survey_processors(&profile, &symbols)
}

/// **Every slot the array names is a record**, and each one is verified by the
/// structure's own claims about itself: `Self` points back at the KPCR,
/// `CurrentPrcb` at the embedded PRCB, and `Number` is the slot index.
#[test]
fn each_processor_block_is_read_and_cross_checked_against_itself() {
    let out = survey(3, &[(KPCR_0, true), (KPCR_1, true), (KPCR_2, true)], true);
    assert_eq!(out.processors.len(), 3);
    assert_eq!(out.claimed, Some(3));
    assert!(out.count_note.is_none(), "{:?}", out.count_note);
    for (index, record) in out.processors.iter().enumerate() {
        assert_eq!(record.index, index as u64);
        assert_eq!(record.kpcr, [KPCR_0, KPCR_1, KPCR_2][index]);
        assert_eq!(record.prcb, record.kpcr + PCR_PRCB);
        assert_eq!(record.self_agrees, Some(true), "{record:?}");
        assert_eq!(record.current_prcb_agrees, Some(true), "{record:?}");
        assert_eq!(record.number_agrees, Some(true), "{record:?}");
        assert!(record.is_coherent());
    }
    assert!(out.is_complete());
}

/// **A KPCR whose `Self` does not point at itself is reported, not dropped.**
/// The record carries both addresses and says they disagree.
#[test]
fn a_self_pointer_that_disagrees_is_reported_on_the_record() {
    let out = survey(2, &[(KPCR_0, true), (KPCR_1, false)], true);
    assert_eq!(out.processors.len(), 2);
    let bad = &out.processors[1];
    assert_eq!(bad.self_pointer, Some(KPCR_1 + 0x10));
    assert_eq!(bad.self_agrees, Some(false));
    assert!(!bad.is_coherent());
    assert_eq!(out.incoherent(), 1);
}

/// **The claimed count and the array are two facts.** When
/// `KeNumberProcessors` says four and the array holds two usable pointers, the
/// array is what was walked and the disagreement is on the record.
#[test]
fn a_count_that_disagrees_with_the_array_is_stated_rather_than_trusted() {
    let out = survey(4, &[(KPCR_0, true), (KPCR_1, true)], true);
    assert_eq!(out.processors.len(), 2);
    assert_eq!(out.claimed, Some(4));
    let note = out
        .count_note
        .as_deref()
        .expect("the disagreement is stated");
    assert!(
        note.contains("reads 4") && note.contains("2 usable"),
        "{note}"
    );
    assert!(!out.is_complete());
}

/// **What each processor was running** is the fact an examiner reads first:
/// the current thread's process, resolved through `_KTHREAD.Process`.
#[test]
fn the_current_threads_process_is_named_when_it_can_be_reached() {
    let out = survey(1, &[(KPCR_0, true)], true);
    let cpu = &out.processors[0];
    assert_eq!(cpu.current_thread, Some(THREAD_0));
    let process = cpu.current_process.as_ref().expect("resolved");
    assert_eq!(process.address, PROCESS_0);
    assert_eq!(process.pid, Some(900));
    assert_eq!(process.name.as_deref(), Some("svchost.exe"));
}

/// **A member this build does not declare is `None`, never a zero.** With no
/// `_KPRCB.Number` the index cross-check is not made, and says so.
#[test]
fn an_undeclared_number_member_leaves_the_check_unmade() {
    let out = survey(1, &[(KPCR_0, true)], false);
    let cpu = &out.processors[0];
    assert_eq!(cpu.number, None);
    assert_eq!(cpu.number_agrees, None);
    assert!(cpu.is_coherent(), "an unmade check is not a failed one");
    let json = out.to_json();
    assert!(json["checks_basis"]
        .as_str()
        .unwrap_or_default()
        .contains("Number"));
}

/// The record says how far the array was probed and why the walk stopped, so
/// a machine with two processors and a machine whose third slot was unreadable
/// do not render alike.
#[test]
fn the_record_states_the_probe_and_the_stop() {
    let out = survey(2, &[(KPCR_0, true), (KPCR_1, true)], true);
    let json = out.to_json();
    assert_eq!(json["processors_walked"], serde_json::json!(2));
    assert_eq!(json["processors_claimed"], serde_json::json!(2));
    assert_eq!(json["slots_probed"], serde_json::json!(3));
    assert!(json["walk_stop"]
        .as_str()
        .unwrap_or_default()
        .contains("null"));
    assert_eq!(json["content_complete"], serde_json::json!(true));
}
