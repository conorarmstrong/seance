//! Console-history recognition on synthetic heaps. The layout under test was
//! derived from a real capture; these pin the *rules* (what is accepted, what
//! is refused, what is reported unreadable) on bytes built to the layout.
// The sweep takes a slice of ranges; one range is the case under test.
#![allow(clippy::single_range_in_vec_init)]

use std::io;

use seance_core::data_source::DataSource;

use crate::console_history::*;

#[derive(Debug)]
struct Heap {
    base: u64,
    bytes: Vec<u8>,
}

impl DataSource for Heap {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset < self.base || offset + buf.len() as u64 > self.base + self.bytes.len() as u64 {
            return Err(io::Error::new(io::ErrorKind::NotFound, "hole"));
        }
        let o = (offset - self.base) as usize;
        buf.copy_from_slice(&self.bytes[o..o + buf.len()]);
        Ok(buf.len())
    }
    fn size(&self) -> u64 {
        u64::MAX
    }
}

const BASE: u64 = 0x1e94_d900_0000;

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// A wide string object at `at`; long text is placed at `data_at`.
fn wstring(heap: &mut [u8], at: usize, text: &str, data_at: usize) {
    let chars = text.encode_utf16().count() as u64;
    let raw = utf16(text);
    let cap: u64 = if chars <= 7 { 7 } else { 15.max(chars | 15) };
    if cap == 7 {
        heap[at..at + raw.len()].copy_from_slice(&raw);
    } else {
        heap[at..at + 8].copy_from_slice(&(BASE + data_at as u64).to_le_bytes());
        heap[data_at..data_at + raw.len()].copy_from_slice(&raw);
    }
    heap[at + 16..at + 24].copy_from_slice(&chars.to_le_bytes());
    heap[at + 24..at + 32].copy_from_slice(&cap.to_le_bytes());
}

/// A heap of `total` bytes holding one history of `commands`: the object at
/// `obj`, the string array at `arr`, long strings from `data`.
fn heap_at(
    commands: &[&str],
    limit: u32,
    app: &str,
    (total, obj, arr, data): (usize, usize, usize, usize),
) -> Vec<u8> {
    let mut h = vec![0u8; total];
    let room = commands.len() + 2;
    h[obj..obj + 8].copy_from_slice(&(BASE + arr as u64).to_le_bytes());
    h[obj + 8..obj + 16]
        .copy_from_slice(&(BASE + (arr + commands.len() * 32) as u64).to_le_bytes());
    h[obj + 16..obj + 24].copy_from_slice(&(BASE + (arr + room * 32) as u64).to_le_bytes());
    h[obj + 0x18..obj + 0x1c].copy_from_slice(&limit.to_le_bytes());
    wstring(&mut h, obj + 0x20, app, data);
    for (i, c) in commands.iter().enumerate() {
        wstring(&mut h, arr + i * 32, c, data + 0x100 + i * 0x100);
    }
    h
}

fn heap_with(commands: &[&str], limit: u32, app: &str) -> Vec<u8> {
    heap_at(commands, limit, app, (0x8000, 0x1000, 0x2000, 0x3000))
}

fn sweep(bytes: Vec<u8>) -> HostSweep {
    let heap = Heap { base: BASE, bytes };
    let end = BASE + heap.bytes.len() as u64;
    sweep_ranges(&heap, &[BASE..end], &ConsoleHistoryConfig::default(), None)
}

#[test]
fn a_history_is_recognised_and_its_commands_read_in_stored_order() {
    let s = sweep(heap_with(
        &["echo one", "hostname", "dir C:\\Users"],
        50,
        "cmd.exe",
    ));
    assert_eq!(s.histories.len(), 1);
    let h = &s.histories[0];
    assert_eq!(h.application, "cmd.exe");
    assert_eq!(h.limit, 50);
    assert_eq!(h.address, BASE + 0x1000);
    let texts: Vec<_> = h.commands.iter().map(|c| c.text.clone().unwrap()).collect();
    assert_eq!(texts, ["echo one", "hostname", "dir C:\\Users"]);
    assert_eq!(h.capacity_commands, 5);
    assert!(h.is_complete());
}

#[test]
fn a_short_command_is_read_from_the_small_string_form() {
    let s = sweep(heap_with(&["cls", "ver"], 50, "cmd.exe"));
    let texts: Vec<_> = s.histories[0]
        .commands
        .iter()
        .map(|c| c.text.clone().unwrap())
        .collect();
    assert_eq!(texts, ["cls", "ver"]);
}

#[test]
fn an_unreadable_command_is_reported_not_dropped() {
    let mut h = heap_with(
        &["echo one", "a rather longer second command"],
        50,
        "cmd.exe",
    );
    // Point the second element's characters at a hole.
    let at = 0x2000 + 32;
    h[at..at + 8].copy_from_slice(&0x1234_0000_0000u64.to_le_bytes());
    let s = sweep(h);
    let hist = &s.histories[0];
    assert_eq!(hist.commands.len(), 2);
    assert_eq!(hist.commands[0].text.as_deref(), Some("echo one"));
    assert!(hist.commands[1].text.is_none());
    assert!(hist.commands[1].unreadable.is_some());
    assert!(!hist.is_complete());
}

#[test]
fn an_implausible_limit_or_name_is_not_a_history() {
    assert!(sweep(heap_with(&["echo one"], 0, "cmd.exe"))
        .histories
        .is_empty());
    assert!(sweep(heap_with(&["echo one"], 0x1_0000, "cmd.exe"))
        .histories
        .is_empty());
    assert!(sweep(heap_with(&["echo one"], 50, "\u{1}\u{2}"))
        .histories
        .is_empty());
}

#[test]
fn a_vector_whose_span_is_not_whole_strings_is_not_a_history() {
    let mut h = heap_with(&["echo one", "hostname"], 50, "cmd.exe");
    let end = u64::from_le_bytes(h[0x1008..0x1010].try_into().unwrap()) + 8;
    h[0x1008..0x1010].copy_from_slice(&end.to_le_bytes());
    assert!(sweep(h).histories.is_empty());
}

#[test]
fn an_empty_heap_and_a_zero_vector_yield_nothing() {
    assert!(sweep(vec![0u8; 0x4000]).histories.is_empty());
}

#[test]
fn a_history_straddling_a_chunk_boundary_is_found_once() {
    // The sweep reads 64 KiB at a time: put the object 0x20 bytes short of
    // the first boundary so its 0x40 bytes span two chunks.
    let s = sweep(heap_at(
        &["echo one", "hostname"],
        50,
        "cmd.exe",
        (0x1_2000, 0xFFE0, 0x1_0400, 0x1_1000),
    ));
    assert_eq!(s.histories.len(), 1, "{:?}", s.histories);
    assert_eq!(s.histories[0].address, BASE + 0xFFE0);
    assert_eq!(s.histories[0].commands.len(), 2);
}

#[test]
fn an_unreadable_heap_is_counted_and_makes_the_host_incomplete() {
    let heap = Heap {
        base: BASE,
        bytes: vec![0u8; 0x1000],
    };
    // Ask for twice what exists.
    let s = sweep_ranges(
        &heap,
        &[BASE..BASE + 0x2000],
        &ConsoleHistoryConfig::default(),
        None,
    );
    assert_eq!(s.bytes_unreadable, 0x1000);
    let host = HostRecord {
        name: "conhost.exe".into(),
        pid: Some(1),
        ppid: Some(0),
        process_address: 0,
        sweep: Some(s),
        not_swept_because: None,
    };
    assert!(!host.is_complete());
}

#[test]
fn a_survey_with_no_host_says_it_is_not_evidence_of_nothing_typed() {
    let survey = ConsoleHistorySurvey {
        hosts: vec![],
        clients: vec![ClientRecord {
            name: "cmd.exe".into(),
            pid: Some(7),
            ppid: Some(1),
        }],
        process_list_complete: true,
    };
    let text = survey.describe();
    assert!(
        text.contains("not evidence that nothing was typed"),
        "{text}"
    );
    assert!(survey.is_complete());
    let j = survey.to_json();
    assert_eq!(j["hosts_total"], 0);
    assert_eq!(j["console_clients_listed"][0]["name"], "cmd.exe");
}

#[test]
fn a_vector_of_something_that_is_not_strings_is_refused_whole() {
    // Same triple, limit and name, but the second element's size exceeds its
    // capacity: a structurally impossible string, so this is another vector.
    let mut h = heap_with(&["echo one", "hostname"], 50, "cmd.exe");
    let at = 0x2000 + 32 + 16;
    h[at..at + 8].copy_from_slice(&100u64.to_le_bytes());
    assert!(sweep(h).histories.is_empty());
}
