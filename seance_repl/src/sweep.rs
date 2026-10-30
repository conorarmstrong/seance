//! `/sweep`: the case-wide byte sweep (`POST /cases/{id}/search/sweep`,
//! ROADMAP §1.2) from the terminal.
//!
//! Two pure halves, so both are tested without a server: the command line
//! becomes the route's body, and the route's answer becomes the lines the
//! pane prints. The printer forwards what the route says. It adds no claim of
//! its own, and it never lets a sweep that a ceiling cut read as finished.

use serde_json::{json, Map, Value};

/// The usage line, printed on a bare `/sweep` and under `/help search`.
pub const SWEEP_USAGE: &str = "/sweep <text> [--bytes <hex>] [--codepage <label>] [--ext <e,..>] \
[--region <r,..>] [--type <T,..>] [--path <prefix>] [--glob <glob>] [--max-hits <n>] \
[--max-bytes <n>] [--resume <artifact_id>:<offset>]";

/// Hits printed before the listing is cut; the count of the rest is printed.
const HITS_SHOWN: usize = 50;

/// `/sweep …` as the route's JSON body.
///
/// The words that are not a flag or a flag's value, joined by single spaces,
/// are one text pattern. `--bytes` adds a byte pattern and may repeat, as may
/// `--codepage`. `--ext`, `--region` and `--type` take comma lists. A flag
/// with no value is an error naming the flag, never silently dropped; so is a
/// sweep with no pattern at all.
pub fn sweep_request_body(command: &str) -> Result<Value, String> {
    let rest = command.trim_start();
    let rest = rest.strip_prefix("/sweep").unwrap_or(rest);
    let words: Vec<&str> = rest.split_whitespace().collect();

    let mut text_words: Vec<&str> = Vec::new();
    let mut byte_patterns: Vec<String> = Vec::new();
    let mut codepages: Vec<String> = Vec::new();
    let mut scope = Map::new();
    let mut bounds = Map::new();
    let mut resume: Option<Value> = None;

    let list = |v: &str| -> Vec<Value> {
        v.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| Value::String(s.to_string()))
            .collect()
    };

    let mut i = 0;
    while i < words.len() {
        let word = words[i];
        if !word.starts_with("--") {
            text_words.push(word);
            i += 1;
            continue;
        }
        let value = match words.get(i + 1) {
            Some(v) if !v.starts_with("--") => *v,
            _ => return Err(format!("{word} needs a value")),
        };
        match word {
            "--bytes" => byte_patterns.push(value.to_string()),
            "--codepage" => codepages.push(value.to_string()),
            "--ext" => {
                scope.insert("extensions".into(), Value::Array(list(value)));
            }
            "--region" => {
                scope.insert("regions".into(), Value::Array(list(value)));
            }
            "--type" => {
                scope.insert("artifact_types".into(), Value::Array(list(value)));
            }
            "--path" => {
                scope.insert("path_prefix".into(), json!(value));
            }
            "--glob" => {
                scope.insert("path_glob".into(), json!(value));
            }
            "--max-hits" => {
                let n: u64 = value
                    .parse()
                    .map_err(|_| format!("--max-hits takes a whole number, not {value:?}"))?;
                bounds.insert("max_hits".into(), json!(n));
            }
            "--max-bytes" => {
                let n: u64 = value
                    .parse()
                    .map_err(|_| format!("--max-bytes takes a whole number, not {value:?}"))?;
                bounds.insert("max_bytes".into(), json!(n));
            }
            "--resume" => resume = Some(parse_cursor(value)?),
            other => return Err(format!("Unknown flag {other}. Usage: {SWEEP_USAGE}")),
        }
        i += 2;
    }

    let mut patterns: Vec<Value> = Vec::new();
    if !text_words.is_empty() {
        patterns.push(json!({"kind": "text", "value": text_words.join(" ")}));
    }
    for hex in byte_patterns {
        patterns.push(json!({"kind": "bytes", "value": hex}));
    }
    if patterns.is_empty() {
        return Err(format!(
            "A sweep needs at least one pattern. Usage: {SWEEP_USAGE}"
        ));
    }

    let mut body = Map::new();
    body.insert("patterns".into(), Value::Array(patterns));
    if !codepages.is_empty() {
        body.insert("codepages".into(), json!(codepages));
    }
    if !scope.is_empty() {
        body.insert("scope".into(), Value::Object(scope));
    }
    if !bounds.is_empty() {
        body.insert("bounds".into(), Value::Object(bounds));
    }
    if let Some(cursor) = resume {
        body.insert("resume".into(), cursor);
    }
    Ok(Value::Object(body))
}

/// `<artifact_id>:<offset>`, the form the printer gives `next_cursor` in.
fn parse_cursor(token: &str) -> Result<Value, String> {
    let malformed = || {
        format!(
            "--resume takes <artifact_id>:<offset> as a previous sweep printed it, not {token:?}"
        )
    };
    let (id, offset) = token.rsplit_once(':').ok_or_else(malformed)?;
    let id = uuid::Uuid::parse_str(id).map_err(|_| malformed())?;
    let offset: u64 = offset.parse().map_err(|_| malformed())?;
    Ok(json!({"artifact_id": id.to_string(), "offset": offset}))
}

/// The route's answer as the lines the pane prints.
///
/// Completeness comes first and is the route's own `complete`: a sweep a
/// ceiling cut says `complete: false` and names every ceiling that bit, with
/// its number, and the `--resume` token to continue. The slack sentence is
/// printed verbatim on every answer, because `slack: 0` alone would read as
/// "no slack held the term".
pub fn format_sweep_response(resp: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let u = |key: &str| resp[key].as_u64().unwrap_or(0);
    let hits = resp["hits"].as_array().cloned().unwrap_or_default();
    let complete = resp["complete"].as_bool() == Some(true);

    out.push(format!(
        "Sweep: {} hit(s), {} object(s) searched, {} byte(s) read ({} ms)",
        hits.len(),
        u("objects_searched"),
        u("bytes_scanned"),
        u("elapsed_ms")
    ));
    out.push(format!("complete: {complete}"));
    if let Some(s) = resp["coverage_statement"].as_str() {
        out.push(format!("Coverage: {s}"));
    }
    if resp["hit_cap_reached"].as_bool() == Some(true) {
        out.push(format!(
            "hit_cap_reached: the hit ceiling of {} was reached (the server's most is {})",
            u("max_hits"),
            u("max_hits_ceiling")
        ));
    }
    if resp["byte_cap_reached"].as_bool() == Some(true) {
        out.push(format!(
            "byte_cap_reached: the byte ceiling of {} was reached (the server's most is {})",
            u("max_bytes"),
            u("max_bytes_ceiling")
        ));
    }
    if resp["object_stream_cut"].as_bool() == Some(true) {
        out.push(format!(
            "object_stream_cut: the case holds more objects than the {} one call pulls",
            u("objects_ceiling")
        ));
    }
    match (
        resp["next_cursor"]["artifact_id"].as_str(),
        resp["next_cursor"]["offset"].as_u64(),
    ) {
        (Some(id), Some(offset)) => {
            out.push(format!("next_cursor: continue with --resume {id}:{offset}"))
        }
        _ if !complete => out.push(
            "next_cursor: none was returned, so this sweep cannot be continued from here; \
             it is still not complete (see the lines above)."
                .to_string(),
        ),
        _ => {}
    }

    if let Some(s) = resp["scope_statement"].as_str() {
        out.push(format!("Scope: {s}"));
    }
    let by_region = |key: &str| -> String {
        resp[key]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| format!("{k}: {}", v.as_u64().unwrap_or(0)))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    };
    out.push(format!(
        "Offered by region: {}",
        by_region("objects_offered_by_region")
    ));
    out.push(format!(
        "Searched by region: {}",
        by_region("objects_searched_by_region")
    ));
    if let Some(s) = resp["slack_statement"].as_str() {
        out.push(format!("Slack: {s}"));
    }
    let names = |key: &str| -> Vec<String> {
        resp[key]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let not_searched = names("regions_not_searched");
    if !not_searched.is_empty() {
        out.push(format!("Regions not searched: {}", not_searched.join(", ")));
    }
    let encodings = names("encodings_searched");
    if !encodings.is_empty() {
        out.push(format!("Encodings searched: {}", encodings.join(", ")));
    }
    let absent = names("codepages_absent");
    if !absent.is_empty() {
        out.push(format!(
            "Code pages not recognised, not searched: {}",
            absent.join(", ")
        ));
    }
    for skipped in resp["encodings_skipped"].as_array().into_iter().flatten() {
        out.push(format!(
            "Pattern {} not searched under {}: {}",
            skipped["pattern_index"].as_u64().unwrap_or(0),
            skipped["encoding"].as_str().unwrap_or("?"),
            skipped["reason"].as_str().unwrap_or("")
        ));
    }
    if u("objects_without_bytes") > 0 {
        out.push(format!(
            "{} object(s) carry no bytes of their own (records, events, directories) and were not searched",
            u("objects_without_bytes")
        ));
    }
    if u("raw_objects_not_offered") > 0 {
        out.push(format!(
            "{} raw image/partition/filesystem/container object(s) were not offered: the scope does not admit raw",
            u("raw_objects_not_offered")
        ));
    }
    for sr in resp["short_reads"].as_array().into_iter().flatten() {
        out.push(format!(
            "Short read: {} ended at {} of a declared {} bytes",
            sr["artifact_id"].as_str().unwrap_or("?"),
            sr["bytes_read"].as_u64().unwrap_or(0),
            sr["declared_size"].as_u64().unwrap_or(0)
        ));
    }
    for rf in resp["read_failures"].as_array().into_iter().flatten() {
        out.push(format!(
            "Read failure: {} at offset {}, not searched past it: {}",
            rf["artifact_id"].as_str().unwrap_or("?"),
            rf["offset"].as_u64().unwrap_or(0),
            rf["error"].as_str().unwrap_or("")
        ));
    }
    for bd in resp["beyond_declared_size"]
        .as_array()
        .into_iter()
        .flatten()
    {
        out.push(format!(
            "Beyond declared size: {} holds {} byte(s) past its declared {}, not searched",
            bd["artifact_id"].as_str().unwrap_or("?"),
            bd["bytes_beyond"].as_u64().unwrap_or(0),
            bd["declared_size"].as_u64().unwrap_or(0)
        ));
    }
    if u("hits_endian_ambiguous") > 0 {
        out.push(format!(
            "{} hit(s) read as the pattern in both UTF-16 byte orders; each names both readings",
            u("hits_endian_ambiguous")
        ));
    }

    for hit in hits.iter().take(HITS_SHOWN) {
        out.push(format_hit(hit));
        for alias in hit["endian_aliases"].as_array().into_iter().flatten() {
            out.push(format!(
                "      also reads as {} at offset {}{} — the bytes do not say which byte order was written",
                alias["encoding"].as_str().unwrap_or("?"),
                alias["offset"].as_u64().unwrap_or(0),
                if alias["folded"].as_bool() == Some(true) {
                    " (folded into this hit)"
                } else {
                    " (reported as its own hit)"
                }
            ));
        }
    }
    if hits.len() > HITS_SHOWN {
        out.push(format!(
            "… {} more hit(s) in this answer are not printed here",
            hits.len() - HITS_SHOWN
        ));
    }
    out
}

fn format_hit(hit: &Value) -> String {
    let encodings: Vec<&str> = hit["encodings"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    format!(
        "  [{}] {} {} @ {} len {} — {:?} [{}]",
        hit["region"].as_str().unwrap_or("?"),
        hit["artifact_id"].as_str().unwrap_or("?"),
        hit["path"].as_str().unwrap_or("(no path)"),
        hit["offset"].as_u64().unwrap_or(0),
        hit["length"].as_u64().unwrap_or(0),
        hit["pattern_value"].as_str().unwrap_or(""),
        encodings.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_args_build_the_route_body() {
        let body = sweep_request_body(
            "/sweep SecretKey --bytes 4d5a --codepage windows-1252 --ext .txt --region raw --max-hits 50",
        )
        .unwrap();
        assert_eq!(
            body,
            json!({
                "patterns": [{"kind": "text", "value": "SecretKey"},
                             {"kind": "bytes", "value": "4d5a"}],
                "codepages": ["windows-1252"],
                "scope": {"extensions": [".txt"], "regions": ["raw"]},
                "bounds": {"max_hits": 50}
            })
        );
    }

    #[test]
    fn a_flag_with_no_value_is_an_error_naming_the_flag() {
        let err = sweep_request_body("/sweep SecretKey --codepage").unwrap_err();
        assert!(err.contains("--codepage"), "{err}");
        let err = sweep_request_body("/sweep SecretKey --ext --region raw").unwrap_err();
        assert!(err.contains("--ext"), "{err}");
    }

    #[test]
    fn a_sweep_with_no_pattern_is_refused() {
        assert!(sweep_request_body("/sweep --region raw").is_err());
    }

    #[test]
    fn sweep_resume_carries_the_cursor() {
        let body =
            sweep_request_body("/sweep x --resume 6f1c1c1e-2b1a-4c1d-9e1f-0a0b0c0d0e0f:4096")
                .unwrap();
        assert_eq!(
            body["resume"],
            json!({"artifact_id": "6f1c1c1e-2b1a-4c1d-9e1f-0a0b0c0d0e0f", "offset": 4096})
        );
        assert!(sweep_request_body("/sweep x --resume notauuid:12").is_err());
        assert!(
            sweep_request_body("/sweep x --resume 6f1c1c1e-2b1a-4c1d-9e1f-0a0b0c0d0e0f").is_err()
        );
        assert!(
            sweep_request_body("/sweep x --resume 6f1c1c1e-2b1a-4c1d-9e1f-0a0b0c0d0e0f:-1")
                .is_err()
        );
    }

    /// A fixture in the route's serialized shape (`SweepResponse` flattened
    /// into `SweepRouteResponse`). Synthetic: it pins what the printer says
    /// about a cut sweep, not any sweep's behaviour on evidence.
    fn cut_sweep() -> Value {
        serde_json::from_str(
            r#"{
            "hits": [{
                "artifact_id": "11111111-1111-4111-8111-111111111111",
                "artifact_type": "FileContent", "region": "live", "path": "/a.txt",
                "offset": 10, "length": 18, "pattern_index": 0, "pattern_kind": "text",
                "pattern_value": "SecretKey", "encodings": ["utf-16le", "utf-16be"],
                "endian_aliases": [{"encoding": "utf-16be", "offset": 9, "folded": true}]
            }],
            "grouping": {"groups": [], "hit_count": 1, "group_count": 1, "hits_without_content_hash": 0},
            "scope": {"regions": ["live", "slack"]},
            "scope_statement": "Searched live and slack; not unallocated, recovered or raw.",
            "regions_searched": ["live", "slack"],
            "regions_not_searched": ["unallocated", "recovered", "raw"],
            "objects_offered": 3, "objects_skipped_by_cursor": 0,
            "objects_excluded": {"artifact_type": 0, "extension": 0, "path": 0, "region": 1},
            "objects_empty": 0, "objects_searched": 2,
            "objects_offered_by_region": {"live": 2, "slack": 0, "raw": 1},
            "objects_searched_by_region": {"live": 2},
            "bytes_scanned": 5000, "bytes_declared": 9000,
            "beyond_declared_size": [], "bytes_beyond_declared_size": 0,
            "hits_endian_ambiguous": 1, "endian_aliases_folded": 1,
            "max_hits": 1, "hit_cap_reached": true, "max_bytes": 4096, "byte_cap_reached": true,
            "next_cursor": {"artifact_id": "11111111-1111-4111-8111-111111111111", "offset": 28},
            "complete": false,
            "coverage_statement": "Stopped at the hit ceiling.",
            "short_reads": [{"artifact_id": "22222222-2222-4222-8222-222222222222", "declared_size": 100, "bytes_read": 40}],
            "read_failures": [{"artifact_id": "33333333-3333-4333-8333-333333333333", "offset": 0, "error": "gone"}],
            "patterns": [{"kind": "text", "value": "SecretKey"}],
            "encodings_searched": ["utf-8", "utf-16le", "utf-16be"],
            "codepages_resolved": [], "codepages_absent": [], "encodings_skipped": [],
            "elapsed_ms": 7,
            "max_hits_ceiling": 10000, "max_bytes_ceiling": 17179869184,
            "chunk_bytes": 1048576, "objects_ceiling": 50000,
            "object_stream_cut": true, "objects_without_bytes": 4, "raw_objects_not_offered": 0,
            "slack_statement": "Slack is offered as the file-slack regions the NTFS, FAT and exFAT parsers publish."
        }"#,
        )
        .unwrap()
    }

    #[test]
    fn a_sweep_answer_prints_every_ceiling_and_never_reads_as_complete_when_cut() {
        let lines = format_sweep_response(&cut_sweep());
        let all = lines.join("\n");
        assert!(all.contains("complete: false"), "{all}");
        assert!(!all.contains("complete: true"), "{all}");
        assert!(
            all.contains("hit_cap_reached") && all.contains("ceiling of 1"),
            "{all}"
        );
        assert!(
            all.contains("byte_cap_reached") && all.contains("ceiling of 4096"),
            "{all}"
        );
        assert!(
            all.contains("object_stream_cut") && all.contains("50000"),
            "{all}"
        );
        assert!(
            all.contains("--resume 11111111-1111-4111-8111-111111111111:28"),
            "{all}"
        );
        assert!(
            all.contains(
                "Slack is offered as the file-slack regions the NTFS, FAT and exFAT parsers publish."
            ),
            "{all}"
        );
        assert!(
            all.contains("Short read") && all.contains("Read failure"),
            "{all}"
        );
    }

    #[test]
    fn the_printed_resume_token_parses_back_into_the_cursor() {
        let lines = format_sweep_response(&cut_sweep());
        let token = lines
            .iter()
            .find_map(|l| l.split("--resume ").nth(1))
            .expect("a resume token");
        let body = sweep_request_body(&format!("/sweep SecretKey --resume {token}")).unwrap();
        assert_eq!(body["resume"], cut_sweep()["next_cursor"]);
    }

    #[test]
    fn an_endian_ambiguous_hit_names_both_readings() {
        let all = format_sweep_response(&cut_sweep()).join("\n");
        assert!(all.contains("utf-16le, utf-16be"), "{all}");
        assert!(all.contains("@ 10"), "{all}");
        assert!(all.contains("also reads as utf-16be at offset 9"), "{all}");
    }

    #[test]
    fn a_complete_sweep_says_so_and_prints_no_cursor() {
        let mut resp = cut_sweep();
        resp["complete"] = json!(true);
        resp["hit_cap_reached"] = json!(false);
        resp["byte_cap_reached"] = json!(false);
        resp["object_stream_cut"] = json!(false);
        resp["next_cursor"] = Value::Null;
        let all = format_sweep_response(&resp).join("\n");
        assert!(all.contains("complete: true"), "{all}");
        assert!(!all.contains("--resume"), "{all}");
        assert!(!all.contains("hit_cap_reached"), "{all}");
    }
}
