#![no_main]

//! The E01 container's in-process trust boundary.
//!
//! The E01 reader deliberately does **not** parse the image itself: libewf is a
//! C library that a malformed E01 can crash, so it runs in a helper subprocess
//! and the parent talks to it over a pipe. That isolation is only worth
//! anything if the parent treats what comes back as hostile — a compromised
//! child can declare a frame length it never sends, claim a payload larger than
//! the caller's buffer, or cut the stream anywhere.
//!
//! So the bytes worth fuzzing are not the image, they are the *responses*.
//! Fuzzing the image would fuzz libewf through a subprocess boundary at a few
//! executions a second and prove nothing about this crate's Rust.

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // The handshake the parent reads when it opens an image.
    let mut cursor = Cursor::new(data);
    let _ = seance_container_e01::isolated::decode_handshake(&mut cursor);

    // A read response, into buffers of several sizes: the clamp between the
    // declared length and the caller's buffer is the property under test, and a
    // single buffer size would only ever exercise one side of it.
    for size in [1usize, 512, 4096] {
        let mut buf = vec![0u8; size];
        let mut cursor = Cursor::new(data);
        let _ = seance_container_e01::isolated::decode_read_response(&mut cursor, &mut buf);
    }

    // The entry-tree walk a logical-mode helper sends after its handshake
    // (HUNT-144): a declared entry count, per-entry frames, and parent links
    // the parent will follow to build paths — every one of them the child's
    // word, and every one bounded or checked before it is believed.
    let mut cursor = Cursor::new(data);
    let _ = seance_container_e01::isolated::decode_logical_walk(&mut cursor);
});
