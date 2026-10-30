#![no_main]

//! Fuzz the email parser plugin across all four supported formats.
//!
//! The first byte of the fuzz input selects which parser branch to exercise
//! (EML / MBOX / MSG / PST); the remaining bytes are the malformed payload.
//! This lets a single corpus drive all four parsers while staying within
//! libfuzzer's single-target model.
//!
//! Goal: the parser must never panic — only `Ok(Vec<Artifact>)` (possibly
//! empty) or `Err(ModuleError)` are acceptable.

use libfuzzer_sys::fuzz_target;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::ByteSliceDataSource,
    module::ForensicsModule,
};
use std::sync::Arc;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 1024 * 1024 {
        return;
    }

    let (selector, body) = data.split_first().unwrap();
    // Each branch picks a (name, subtype) pair to drive a different routing
    // path in `EmailParser::process`:
    //   - `subtype = "mbox"` → process_mbox fast path
    //   - `subtype = "eml"` / `"msg"` → format-specific dispatch
    //   - no subtype → content + extension auto-detection path
    let (name, subtype): (&str, Option<&str>) = match selector % 5 {
        0 => ("fuzz.eml", Some("eml")),
        1 => ("fuzz.mbox", Some("mbox")),
        2 => ("fuzz.msg", Some("msg")),
        3 => ("fuzz.pst", None),
        _ => ("fuzz_no_extension", None),
    };

    let mut meta = serde_json::json!({ "name": name });
    if let Some(s) = subtype {
        meta["subtype"] = serde_json::Value::String(s.to_string());
    }

    let ds = Arc::new(ByteSliceDataSource::new(body.to_vec()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        meta,
    );

    let parser = seance_plugin_email::EmailParser;
    let _ = parser.process(&artifact);
});
