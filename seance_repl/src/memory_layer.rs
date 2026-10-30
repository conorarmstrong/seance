//! `/memory layer` — save a memory image's decoded physical layer and its hole
//! manifest (ROADMAP §5.3, the `layerwriter` equivalent).
//!
//! The REPL fetches `GET …/memory/layer/{image}/manifest` first and writes it
//! beside the raw file, then streams `GET …/memory/layer/{image}/raw` to disk
//! chunk by chunk. The saved pair is only called complete when the raw file is
//! the planned size, the transfer ended without an error, and the raw
//! response's `X-Layer-Manifest-Sha256` names the manifest that was saved. Any
//! other outcome is reported as a fragment that must not be tendered.
//!
//! The halves here are pure so they can be pinned without a server.

use serde_json::Value;

/// What `/memory layer` was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerArgs {
    pub image: String,
    pub start: Option<u64>,
    pub end: Option<u64>,
}

pub const LAYER_USAGE: &str = "Usage: /memory layer <image_id> [--start <addr>] [--end <addr>] \
     - save the image's decoded physical layer as a raw file with its hole manifest \
     (addresses decimal or 0x-hex; --end is exclusive)";

/// Parse `/memory layer <image_id> [--start n] [--end n]`.
///
/// An unknown flag, a flag with no value or a value that is not a number is
/// refused with the flag named, never dropped: an export of the whole layer
/// when a range was meant is a different exhibit.
pub fn parse_layer_args(parts: &[&str]) -> Result<LayerArgs, String> {
    let Some(image) = parts.get(2).filter(|p| !p.starts_with("--")) else {
        return Err(LAYER_USAGE.to_string());
    };
    let mut args = LayerArgs {
        image: (*image).to_string(),
        start: None,
        end: None,
    };
    let mut rest = parts[3..].iter();
    while let Some(flag) = rest.next() {
        let slot = match *flag {
            "--start" => &mut args.start,
            "--end" => &mut args.end,
            other => return Err(format!("Unknown flag {other}. {LAYER_USAGE}")),
        };
        let Some(value) = rest.next() else {
            return Err(format!("{flag} needs an address. {LAYER_USAGE}"));
        };
        let parsed = match value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => value.parse::<u64>(),
        };
        *slot = Some(parsed.map_err(|_| {
            format!("{flag} {value} is not an address (decimal or 0x-hex). {LAYER_USAGE}")
        })?);
    }
    Ok(args)
}

/// The manifest and raw URLs for `args`.
pub fn layer_urls(api: &str, case: &str, args: &LayerArgs) -> (String, String) {
    let mut query = Vec::new();
    if let Some(start) = args.start {
        query.push(format!("start={start}"));
    }
    if let Some(end) = args.end {
        query.push(format!("end={end}"));
    }
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{}", query.join("&"))
    };
    let base = format!("{api}/api/v1/cases/{case}/memory/layer/{}", args.image);
    (
        format!("{base}/manifest{query}"),
        format!("{base}/raw{query}"),
    )
}

/// The base file name both saved files share: `<stem>.raw` and
/// `<stem>.manifest.json`. A range is part of the name, in hex, so two exports
/// of different ranges of one image cannot overwrite each other.
pub fn layer_file_stem(args: &LayerArgs) -> String {
    match (args.start, args.end) {
        (None, None) => format!("seance_layer_{}", args.image),
        (start, end) => format!(
            "seance_layer_{}_{:x}-{}",
            args.image,
            start.unwrap_or(0),
            end.map(|e| format!("{e:x}"))
                .unwrap_or_else(|| "end".to_string())
        ),
    }
}

/// What the saved raw file amounts to.
///
/// `complete` only when every planned byte arrived, the transfer ended without
/// an error and the raw response named the manifest that was saved; otherwise
/// `FRAGMENT`, with the reason.
pub fn layer_verdict(
    expected_bytes: u64,
    written_bytes: u64,
    manifest_sha256: &str,
    header_sha256: Option<&str>,
    stream_error: Option<&str>,
) -> String {
    let mut faults = Vec::new();
    if let Some(error) = stream_error {
        faults.push(format!("the transfer stopped: {error}"));
    }
    if written_bytes != expected_bytes {
        faults.push(format!(
            "{written_bytes} of {expected_bytes} planned bytes arrived"
        ));
    }
    match header_sha256 {
        Some(h) if h == manifest_sha256 => {}
        Some(h) => faults.push(format!(
            "the raw file names manifest {h}, not the saved one ({manifest_sha256})"
        )),
        None => faults.push("the raw response named no manifest".to_string()),
    }
    if faults.is_empty() {
        format!(
            "complete: {written_bytes} bytes, described by the saved manifest \
             (sha256 {manifest_sha256})"
        )
    } else {
        format!("FRAGMENT — do not tender this file: {}", faults.join("; "))
    }
}

/// The lines printed about a manifest before the download starts.
pub fn manifest_summary(response: &Value) -> Vec<String> {
    let m = &response["manifest"];
    let n = |key: &str| m[key].as_u64().unwrap_or(0);
    let mut lines = vec![format!(
        "Layer: {} bytes, {} read from the acquisition, {} bytes of fill in {} hole(s) \
         (fill byte 0x{:02x})",
        n("total_bytes"),
        n("backed_bytes"),
        n("hole_bytes"),
        n("hole_count"),
        n("fill_byte")
    )];
    if let Some(statement) = m["statement"].as_str() {
        lines.push(statement.to_string());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_arguments_parse_with_decimal_and_hex_addresses() {
        assert_eq!(
            parse_layer_args(&["/memory", "layer", "abc"]).unwrap(),
            LayerArgs {
                image: "abc".into(),
                start: None,
                end: None
            }
        );
        assert_eq!(
            parse_layer_args(&["/memory", "layer", "abc", "--start", "0x1000", "--end", "8192"])
                .unwrap(),
            LayerArgs {
                image: "abc".into(),
                start: Some(0x1000),
                end: Some(8192)
            }
        );
    }

    #[test]
    fn a_malformed_or_unknown_flag_is_refused_not_dropped() {
        assert!(parse_layer_args(&["/memory", "layer"]).is_err());
        assert!(parse_layer_args(&["/memory", "layer", "abc", "--start"]).is_err());
        assert!(parse_layer_args(&["/memory", "layer", "abc", "--start", "zz"]).is_err());
        let err = parse_layer_args(&["/memory", "layer", "abc", "--pad"]).unwrap_err();
        assert!(err.contains("--pad"), "{err}");
    }

    #[test]
    fn the_urls_carry_the_range() {
        let args = LayerArgs {
            image: "img".into(),
            start: Some(4096),
            end: None,
        };
        let (manifest, raw) = layer_urls("http://h:8080", "case", &args);
        assert_eq!(
            manifest,
            "http://h:8080/api/v1/cases/case/memory/layer/img/manifest?start=4096"
        );
        assert_eq!(
            raw,
            "http://h:8080/api/v1/cases/case/memory/layer/img/raw?start=4096"
        );
        let whole = LayerArgs {
            image: "img".into(),
            start: None,
            end: None,
        };
        assert!(layer_urls("http://h", "c", &whole).1.ends_with("/raw"));
        assert_eq!(layer_file_stem(&whole), "seance_layer_img");
        assert_eq!(layer_file_stem(&args), "seance_layer_img_1000-end");
    }

    #[test]
    fn only_a_full_file_naming_its_manifest_is_called_complete() {
        let ok = layer_verdict(100, 100, "aa", Some("aa"), None);
        assert!(ok.starts_with("complete"), "{ok}");
        for bad in [
            layer_verdict(100, 60, "aa", Some("aa"), None),
            layer_verdict(100, 100, "aa", Some("bb"), None),
            layer_verdict(100, 100, "aa", None, None),
            layer_verdict(100, 60, "aa", Some("aa"), Some("reset")),
        ] {
            assert!(bad.starts_with("FRAGMENT"), "{bad}");
        }
    }

    #[test]
    fn the_summary_states_the_fill_before_anything_is_saved() {
        let lines = manifest_summary(&json!({
            "manifest": {
                "total_bytes": 20480, "backed_bytes": 12288, "hole_bytes": 8192,
                "hole_count": 2, "fill_byte": 0,
                "statement": "This file holds 20480 bytes ..."
            },
            "manifest_sha256": "ab"
        }));
        let text = lines.join("\n");
        assert!(text.contains("20480 bytes"), "{text}");
        assert!(text.contains("8192 bytes of fill in 2 hole(s)"), "{text}");
        assert!(text.contains("This file holds"), "{text}");
    }
}
