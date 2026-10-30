use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A filter condition that can be simple, compound (AND/OR), or negated (NOT).
///
/// Filters evaluate against an artifact's type and metadata JSON.
///
/// # Examples
///
/// Simple filter: files with .exe extension
/// ```json
/// {"type": "simple", "field": "extension", "operator": "eq", "value": "exe"}
/// ```
///
/// Compound filter: deleted executables
/// ```json
/// {"type": "compound", "logic": "and", "conditions": [
///   {"type": "simple", "field": "deleted", "operator": "eq", "value": true},
///   {"type": "simple", "field": "extension", "operator": "in", "value": ["exe","dll","sys"]}
/// ]}
/// ```
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum FilterCondition {
    #[serde(rename = "simple")]
    Simple {
        field: String,
        operator: FilterOp,
        value: Value,
    },
    #[serde(rename = "compound")]
    Compound {
        logic: LogicOp,
        conditions: Vec<FilterCondition>,
    },
    #[serde(rename = "not")]
    Not { condition: Box<FilterCondition> },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    Eq,
    Neq,
    Gt,
    Lt,
    Gte,
    Lte,
    Contains,
    StartsWith,
    EndsWith,
    In,
    Exists,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LogicOp {
    And,
    Or,
}

const MAX_FILTER_DEPTH: usize = 32;

impl FilterCondition {
    /// Nesting depth of the deepest node, counting the root as 0.
    pub fn depth(&self) -> usize {
        match self {
            FilterCondition::Simple { .. } => 0,
            FilterCondition::Compound { conditions, .. } => conditions
                .iter()
                .map(Self::depth)
                .max()
                .map_or(0, |d| d + 1),
            FilterCondition::Not { condition } => condition.depth() + 1,
        }
    }

    /// Refuse a filter nested deeper than the evaluator will look.
    ///
    /// `evaluate` answers `false` for a node past the limit, which a `Not`
    /// ancestor turns into `true`: artifacts that were never examined would
    /// match. Callers that accept a filter from outside (save, load, scan) must
    /// call this first so an over-deep filter is an error, not a quiet wrong
    /// answer.
    pub fn validate(&self) -> Result<(), String> {
        let depth = self.depth();
        if depth > MAX_FILTER_DEPTH {
            return Err(format!(
                "filter is nested {depth} levels deep; the limit is {MAX_FILTER_DEPTH}"
            ));
        }
        Ok(())
    }

    /// Evaluate this filter against an artifact's type string and metadata JSON.
    pub fn evaluate(&self, artifact_type: &str, metadata: &Value) -> bool {
        self.evaluate_inner(artifact_type, metadata, 0)
    }

    fn evaluate_inner(&self, artifact_type: &str, metadata: &Value, depth: usize) -> bool {
        if depth > MAX_FILTER_DEPTH {
            return false; // Prevent stack overflow from deeply nested filters
        }
        match self {
            FilterCondition::Simple {
                field,
                operator,
                value,
            } => {
                let actual = resolve_field(field, artifact_type, metadata);
                evaluate_op(operator, &actual, value)
            }
            FilterCondition::Compound { logic, conditions } => match logic {
                LogicOp::And => conditions
                    .iter()
                    .all(|c| c.evaluate_inner(artifact_type, metadata, depth + 1)),
                LogicOp::Or => conditions
                    .iter()
                    .any(|c| c.evaluate_inner(artifact_type, metadata, depth + 1)),
            },
            FilterCondition::Not { condition } => {
                !condition.evaluate_inner(artifact_type, metadata, depth + 1)
            }
        }
    }
}

/// Extension of a file name: the text after its last dot, lower-cased.
///
/// `None` when there is no dot, when the dot is the last character, or when the
/// suffix is implausibly long (10+ characters), which is a dotted file name
/// rather than an extension (`archive.2026-07-28-backup`).
fn extension_of(name: &str) -> Option<String> {
    let last = name.rsplit(['/', '\\']).next()?;
    let dot_pos = last.rfind('.')?;
    let ext = &last[dot_pos + 1..];
    if ext.is_empty() || ext.len() >= 10 {
        return None;
    }
    Some(ext.to_lowercase())
}

/// Resolve a field name to its actual value from the artifact.
///
/// Special fields:
/// - `artifact_type`: the artifact's type string (e.g. "FileEntry")
/// - `extension`: an explicit `extension` field if the parser recorded one,
///   else derived from `name`, else from the last segment of `path`
/// - All others: looked up directly in the metadata JSON
///
/// Forensically, `extension` is what the built-in "All Graphics"/"All
/// Documents" filters key on. Deriving it from `name` alone silently dropped
/// every record whose metadata carries only a full `path` (plenty of
/// filesystem parsers record one and not the other), so an examiner filtering
/// for pictures saw a short list that looked like the complete set.
fn resolve_field(field: &str, artifact_type: &str, metadata: &Value) -> Value {
    match field {
        "artifact_type" => json!(artifact_type),
        "extension" => metadata
            .get("extension")
            .and_then(|v| v.as_str())
            .map(|e| e.trim_start_matches('.').to_lowercase())
            .filter(|e| !e.is_empty())
            .or_else(|| {
                metadata
                    .get("name")
                    .and_then(|v| v.as_str())
                    .and_then(extension_of)
            })
            .or_else(|| {
                metadata
                    .get("path")
                    .or_else(|| metadata.get("source_path"))
                    .and_then(|v| v.as_str())
                    .and_then(extension_of)
            })
            .map(|e| json!(e))
            .unwrap_or(json!(null)),
        _ => metadata.get(field).cloned().unwrap_or(json!(null)),
    }
}

/// Evaluate a comparison operator between an actual value and a filter value.
fn evaluate_op(op: &FilterOp, actual: &Value, expected: &Value) -> bool {
    match op {
        FilterOp::Eq => values_equal(actual, expected),
        FilterOp::Neq => !values_equal(actual, expected),
        FilterOp::Gt => compare_values(actual, expected) == Some(std::cmp::Ordering::Greater),
        FilterOp::Lt => compare_values(actual, expected) == Some(std::cmp::Ordering::Less),
        FilterOp::Gte => matches!(
            compare_values(actual, expected),
            Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
        ),
        FilterOp::Lte => matches!(
            compare_values(actual, expected),
            Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
        ),
        FilterOp::Contains => {
            if let (Some(haystack), Some(needle)) = (actual.as_str(), expected.as_str()) {
                haystack.to_lowercase().contains(&needle.to_lowercase())
            } else {
                false
            }
        }
        FilterOp::StartsWith => {
            if let (Some(haystack), Some(prefix)) = (actual.as_str(), expected.as_str()) {
                haystack.to_lowercase().starts_with(&prefix.to_lowercase())
            } else {
                false
            }
        }
        FilterOp::EndsWith => {
            if let (Some(haystack), Some(suffix)) = (actual.as_str(), expected.as_str()) {
                haystack.to_lowercase().ends_with(&suffix.to_lowercase())
            } else {
                false
            }
        }
        FilterOp::In => {
            if let Some(list) = expected.as_array() {
                list.iter().any(|item| values_equal(actual, item))
            } else {
                false
            }
        }
        FilterOp::Exists => !actual.is_null(),
    }
}

/// Case-insensitive equality for strings, standard equality for others.
fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(s1), Value::String(s2)) => s1.to_lowercase() == s2.to_lowercase(),
        (Value::Number(n1), Value::Number(n2)) => {
            // Compare as f64 to handle int/float mismatches
            n1.as_f64() == n2.as_f64()
        }
        (Value::Bool(b1), Value::Bool(b2)) => b1 == b2,
        (Value::Null, Value::Null) => true,
        // Allow comparing bool-string: "true"/"false" vs true/false
        (Value::Bool(b1), Value::String(s)) | (Value::String(s), Value::Bool(b1)) => {
            match s.to_lowercase().as_str() {
                "true" | "1" => *b1,
                "false" | "0" => !*b1,
                _ => false,
            }
        }
        _ => a == b,
    }
}

/// Compare two values for ordering (numbers and strings only).
///
/// Strings order case-insensitively, matching [`values_equal`]. When ordering
/// was case-SENSITIVE and equality was not, the same filter answered
/// inconsistently for the same pair of values: `name eq "m"` matched "M" while
/// `name gte "m"` did not, so an examiner's ordered name/path range silently
/// excluded every capitalised entry (ASCII upper-case sorts before all
/// lower-case).
fn compare_values(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    match (a, b) {
        (Value::Number(n1), Value::Number(n2)) => n1.as_f64()?.partial_cmp(&n2.as_f64()?),
        (Value::String(s1), Value::String(s2)) => Some(s1.to_lowercase().cmp(&s2.to_lowercase())),
        _ => None,
    }
}

/// Built-in predefined filter definitions.
pub fn predefined_filters() -> Vec<(&'static str, &'static str, FilterCondition)> {
    vec![
        (
            "All Graphics",
            "Image files (JPEG, PNG, GIF, BMP, TIFF, WebP, SVG, ICO)",
            FilterCondition::Simple {
                field: "extension".to_string(),
                operator: FilterOp::In,
                value: json!([
                    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif", "webp", "svg", "ico", "raw",
                    "cr2", "nef"
                ]),
            },
        ),
        (
            "All Documents",
            "Document files (Office, PDF, text)",
            FilterCondition::Simple {
                field: "extension".to_string(),
                operator: FilterOp::In,
                value: json!([
                    "doc", "docx", "pdf", "txt", "rtf", "xls", "xlsx", "ppt", "pptx", "odt", "ods",
                    "odp", "csv", "md", "tex"
                ]),
            },
        ),
        (
            "All Executables",
            "Executable and script files",
            FilterCondition::Simple {
                field: "extension".to_string(),
                operator: FilterOp::In,
                value: json!([
                    "exe", "dll", "sys", "bat", "cmd", "ps1", "sh", "msi", "com", "scr", "vbs",
                    "js", "wsf", "jar"
                ]),
            },
        ),
        (
            "Encrypted Files",
            "Files detected as encrypted by a format signature or NTFS EFS; high-entropy leads are not included",
            FilterCondition::Compound {
                logic: LogicOp::Or,
                conditions: vec![
                    FilterCondition::Simple {
                        field: "efs_encrypted".to_string(),
                        operator: FilterOp::Eq,
                        value: json!(true),
                    },
                    // HUNT-180: only a signature-backed detection asserts
                    // `is_encrypted`; an entropy-only lead does not.
                    FilterCondition::Simple {
                        field: "is_encrypted".to_string(),
                        operator: FilterOp::Eq,
                        value: json!(true),
                    },
                ],
            },
        ),
        (
            "Email Messages",
            "Parsed email messages and mailbox files",
            FilterCondition::Compound {
                logic: LogicOp::Or,
                conditions: vec![
                    FilterCondition::Simple {
                        field: "analysis_type".to_string(),
                        operator: FilterOp::Eq,
                        value: json!("email"),
                    },
                    FilterCondition::Simple {
                        field: "extension".to_string(),
                        operator: FilterOp::In,
                        value: json!(["eml", "msg", "mbox", "mbx", "pst"]),
                    },
                ],
            },
        ),
        (
            "Signature Mismatches",
            "Files where content type doesn't match extension",
            FilterCondition::Simple {
                field: "signature_mismatch".to_string(),
                operator: FilterOp::Eq,
                value: json!(true),
            },
        ),
        (
            "Deleted Files",
            "Files marked as deleted in filesystem metadata",
            FilterCondition::Simple {
                field: "deleted".to_string(),
                operator: FilterOp::Eq,
                value: json!(true),
            },
        ),
        (
            "Alternate Data Streams",
            "NTFS Alternate Data Streams (potential data hiding)",
            FilterCondition::Simple {
                field: "is_ads".to_string(),
                operator: FilterOp::Eq,
                value: json!(true),
            },
        ),
        (
            "Large Files (>100MB)",
            "Files larger than 100 megabytes",
            FilterCondition::Simple {
                field: "size".to_string(),
                operator: FilterOp::Gt,
                value: json!(104_857_600),
            },
        ),
        (
            "Archives",
            "Compressed archive files",
            FilterCondition::Simple {
                field: "extension".to_string(),
                operator: FilterOp::In,
                value: json!(["zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab", "iso"]),
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_eq_string() {
        let filter = FilterCondition::Simple {
            field: "name".to_string(),
            operator: FilterOp::Eq,
            value: json!("test.txt"),
        };
        assert!(filter.evaluate("FileEntry", &json!({"name": "test.txt"})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "other.txt"})));
    }

    #[test]
    fn test_simple_eq_case_insensitive() {
        let filter = FilterCondition::Simple {
            field: "name".to_string(),
            operator: FilterOp::Eq,
            value: json!("TEST.TXT"),
        };
        assert!(filter.evaluate("FileEntry", &json!({"name": "test.txt"})));
    }

    #[test]
    fn test_extension_derived() {
        let filter = FilterCondition::Simple {
            field: "extension".to_string(),
            operator: FilterOp::Eq,
            value: json!("jpg"),
        };
        assert!(filter.evaluate("FileEntry", &json!({"name": "photo.JPG"})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "photo.png"})));
    }

    #[test]
    fn test_extension_in_list() {
        let filter = FilterCondition::Simple {
            field: "extension".to_string(),
            operator: FilterOp::In,
            value: json!(["jpg", "jpeg", "png"]),
        };
        assert!(filter.evaluate("FileEntry", &json!({"name": "a.jpg"})));
        assert!(filter.evaluate("FileEntry", &json!({"name": "b.PNG"})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "c.gif"})));
    }

    #[test]
    fn test_compound_and() {
        let filter = FilterCondition::Compound {
            logic: LogicOp::And,
            conditions: vec![
                FilterCondition::Simple {
                    field: "deleted".to_string(),
                    operator: FilterOp::Eq,
                    value: json!(true),
                },
                FilterCondition::Simple {
                    field: "extension".to_string(),
                    operator: FilterOp::Eq,
                    value: json!("exe"),
                },
            ],
        };
        assert!(filter.evaluate(
            "FileEntry",
            &json!({"name": "malware.exe", "deleted": true})
        ));
        assert!(!filter.evaluate(
            "FileEntry",
            &json!({"name": "malware.exe", "deleted": false})
        ));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "readme.txt", "deleted": true})));
    }

    #[test]
    fn test_compound_or() {
        let filter = FilterCondition::Compound {
            logic: LogicOp::Or,
            conditions: vec![
                FilterCondition::Simple {
                    field: "extension".to_string(),
                    operator: FilterOp::Eq,
                    value: json!("exe"),
                },
                FilterCondition::Simple {
                    field: "extension".to_string(),
                    operator: FilterOp::Eq,
                    value: json!("dll"),
                },
            ],
        };
        assert!(filter.evaluate("FileEntry", &json!({"name": "a.exe"})));
        assert!(filter.evaluate("FileEntry", &json!({"name": "b.dll"})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "c.txt"})));
    }

    #[test]
    fn test_not() {
        let filter = FilterCondition::Not {
            condition: Box::new(FilterCondition::Simple {
                field: "is_directory".to_string(),
                operator: FilterOp::Eq,
                value: json!(true),
            }),
        };
        assert!(filter.evaluate("FileEntry", &json!({"name": "file.txt"})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "dir", "is_directory": true})));
    }

    #[test]
    fn test_numeric_comparison() {
        let filter = FilterCondition::Simple {
            field: "size".to_string(),
            operator: FilterOp::Gt,
            value: json!(1024),
        };
        assert!(filter.evaluate("FileEntry", &json!({"name": "big.bin", "size": 2048})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "small.bin", "size": 512})));
    }

    #[test]
    fn test_contains() {
        let filter = FilterCondition::Simple {
            field: "name".to_string(),
            operator: FilterOp::Contains,
            value: json!("secret"),
        };
        assert!(filter.evaluate("FileEntry", &json!({"name": "my_Secret_file.txt"})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "normal.txt"})));
    }

    #[test]
    fn test_exists() {
        let filter = FilterCondition::Simple {
            field: "deleted".to_string(),
            operator: FilterOp::Exists,
            value: json!(null),
        };
        assert!(filter.evaluate("FileEntry", &json!({"name": "a.txt", "deleted": true})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "b.txt"})));
    }

    #[test]
    fn test_artifact_type_filter() {
        let filter = FilterCondition::Simple {
            field: "artifact_type".to_string(),
            operator: FilterOp::Eq,
            value: json!("FileEntry"),
        };
        assert!(filter.evaluate("FileEntry", &json!({})));
        assert!(!filter.evaluate("Container", &json!({})));
    }

    #[test]
    fn test_predefined_filters_valid() {
        let filters = predefined_filters();
        assert!(filters.len() >= 8);
        // Each predefined filter should be valid
        for (name, _desc, condition) in &filters {
            // Smoke test: evaluate against empty metadata should not panic
            condition.evaluate("FileEntry", &json!({"name": "test.txt"}));
            assert!(!name.is_empty());
            assert!(condition.validate().is_ok(), "{name} is nested too deeply");
        }
    }

    // === Edge case: filter depth limit ===

    #[test]
    fn test_depth_limit_at_max() {
        // Build a filter nested exactly MAX_FILTER_DEPTH (32) levels deep
        let mut filter = FilterCondition::Simple {
            field: "name".to_string(),
            operator: FilterOp::Eq,
            value: json!("test.txt"),
        };
        for _ in 0..MAX_FILTER_DEPTH {
            filter = FilterCondition::Not {
                condition: Box::new(filter),
            };
        }
        // 32 levels of NOT around a simple filter — should still evaluate
        // (32 NOTs = even number = same as original for even, negated for odd)
        let meta = json!({"name": "test.txt"});
        // The depth check is > MAX_FILTER_DEPTH, so 32 is still evaluated.
        // An even number of NOTs leaves the answer unchanged: it matches.
        assert!(filter.evaluate("FileEntry", &meta));
        assert!(filter.validate().is_ok());
    }

    fn and_chain(levels: usize) -> FilterCondition {
        let mut filter = FilterCondition::Simple {
            field: "name".to_string(),
            operator: FilterOp::Eq,
            value: json!("test.txt"),
        };
        for _ in 0..levels {
            filter = FilterCondition::Compound {
                logic: LogicOp::And,
                conditions: vec![filter],
            };
        }
        filter
    }

    #[test]
    fn the_depth_boundary_is_exactly_max_filter_depth() {
        let meta = json!({"name": "test.txt"});
        let at = and_chain(MAX_FILTER_DEPTH);
        assert!(at.evaluate("FileEntry", &meta));
        assert!(at.validate().is_ok());
        let over = and_chain(MAX_FILTER_DEPTH + 1);
        assert!(!over.evaluate("FileEntry", &meta));
        assert!(over.validate().is_err());
    }

    /// A Not turns the evaluator's `false` for an unexamined node into `true`,
    /// so an over-deep Not chain must be refused, not evaluated.
    #[test]
    fn an_over_deep_not_chain_is_refused() {
        let mut filter = and_chain(0);
        for _ in 0..34 {
            filter = FilterCondition::Not {
                condition: Box::new(filter),
            };
        }
        assert_eq!(filter.depth(), 34);
        assert!(filter.validate().is_err());
    }

    #[test]
    fn test_depth_limit_exceeds_max() {
        // Build a filter nested MAX_FILTER_DEPTH + 5 levels deep using AND compounds
        // (AND propagates false upward without inversion, unlike NOT)
        let mut filter = FilterCondition::Simple {
            field: "name".to_string(),
            operator: FilterOp::Eq,
            value: json!("test.txt"),
        };
        for _ in 0..MAX_FILTER_DEPTH + 5 {
            filter = FilterCondition::Compound {
                logic: LogicOp::And,
                conditions: vec![filter],
            };
        }
        // The innermost Simple filter is at depth 37, exceeding MAX_FILTER_DEPTH (32)
        // evaluate_inner returns false at depth > 32, AND propagates false upward
        let result = filter.evaluate("FileEntry", &json!({"name": "test.txt"}));
        assert!(
            !result,
            "Deeply nested filter should return false when exceeding max depth"
        );
    }

    // === Edge case: untested operators ===

    #[test]
    fn test_neq_operator() {
        let filter = FilterCondition::Simple {
            field: "name".to_string(),
            operator: FilterOp::Neq,
            value: json!("test.txt"),
        };
        assert!(!filter.evaluate("FileEntry", &json!({"name": "test.txt"})));
        assert!(filter.evaluate("FileEntry", &json!({"name": "other.txt"})));
    }

    #[test]
    fn test_lt_operator() {
        let filter = FilterCondition::Simple {
            field: "size".to_string(),
            operator: FilterOp::Lt,
            value: json!(1024),
        };
        assert!(filter.evaluate("FileEntry", &json!({"name": "a", "size": 512})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "a", "size": 1024})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "a", "size": 2048})));
    }

    #[test]
    fn test_gte_operator() {
        let filter = FilterCondition::Simple {
            field: "size".to_string(),
            operator: FilterOp::Gte,
            value: json!(1024),
        };
        assert!(!filter.evaluate("FileEntry", &json!({"name": "a", "size": 512})));
        assert!(filter.evaluate("FileEntry", &json!({"name": "a", "size": 1024})));
        assert!(filter.evaluate("FileEntry", &json!({"name": "a", "size": 2048})));
    }

    #[test]
    fn test_lte_operator() {
        let filter = FilterCondition::Simple {
            field: "size".to_string(),
            operator: FilterOp::Lte,
            value: json!(1024),
        };
        assert!(filter.evaluate("FileEntry", &json!({"name": "a", "size": 512})));
        assert!(filter.evaluate("FileEntry", &json!({"name": "a", "size": 1024})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "a", "size": 2048})));
    }

    #[test]
    fn test_starts_with_operator() {
        let filter = FilterCondition::Simple {
            field: "name".to_string(),
            operator: FilterOp::StartsWith,
            value: json!("secret"),
        };
        assert!(filter.evaluate("FileEntry", &json!({"name": "Secret_plans.docx"})));
        assert!(filter.evaluate("FileEntry", &json!({"name": "secret_stuff.txt"})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "my_secret.txt"})));
    }

    #[test]
    fn test_ends_with_operator() {
        let filter = FilterCondition::Simple {
            field: "name".to_string(),
            operator: FilterOp::EndsWith,
            value: json!(".exe"),
        };
        assert!(filter.evaluate("FileEntry", &json!({"name": "malware.EXE"})));
        assert!(filter.evaluate("FileEntry", &json!({"name": "app.exe"})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "executable"})));
    }

    // === Edge case: IN with empty list ===

    #[test]
    fn test_in_empty_list() {
        let filter = FilterCondition::Simple {
            field: "extension".to_string(),
            operator: FilterOp::In,
            value: json!([]),
        };
        assert!(!filter.evaluate("FileEntry", &json!({"name": "test.txt"})));
    }

    #[test]
    fn test_in_non_array_value() {
        let filter = FilterCondition::Simple {
            field: "extension".to_string(),
            operator: FilterOp::In,
            value: json!("not_an_array"),
        };
        assert!(!filter.evaluate("FileEntry", &json!({"name": "test.txt"})));
    }

    // === Edge case: null / missing values ===

    #[test]
    fn test_eq_null_values() {
        let filter = FilterCondition::Simple {
            field: "deleted".to_string(),
            operator: FilterOp::Eq,
            value: json!(null),
        };
        // Missing field = null, should match null
        assert!(filter.evaluate("FileEntry", &json!({"name": "a.txt"})));
        assert!(!filter.evaluate("FileEntry", &json!({"name": "a.txt", "deleted": true})));
    }

    #[test]
    fn test_comparison_mismatched_types() {
        // Comparing a string with a number should not match
        let filter = FilterCondition::Simple {
            field: "size".to_string(),
            operator: FilterOp::Gt,
            value: json!(1024),
        };
        // size is a string "2048" — should not compare as number
        assert!(!filter.evaluate("FileEntry", &json!({"name": "a", "size": "2048"})));
    }

    // === Edge case: bool-string comparison ===

    #[test]
    fn test_bool_string_equality() {
        let filter = FilterCondition::Simple {
            field: "deleted".to_string(),
            operator: FilterOp::Eq,
            value: json!("true"),
        };
        assert!(filter.evaluate("FileEntry", &json!({"deleted": true})));
        assert!(!filter.evaluate("FileEntry", &json!({"deleted": false})));
    }

    #[test]
    fn test_bool_string_equality_reverse() {
        let filter = FilterCondition::Simple {
            field: "deleted".to_string(),
            operator: FilterOp::Eq,
            value: json!(true),
        };
        assert!(filter.evaluate("FileEntry", &json!({"deleted": "true"})));
        assert!(filter.evaluate("FileEntry", &json!({"deleted": "1"})));
        assert!(!filter.evaluate("FileEntry", &json!({"deleted": "false"})));
        assert!(!filter.evaluate("FileEntry", &json!({"deleted": "0"})));
    }

    // === Edge case: extension handling ===

    #[test]
    fn test_extension_no_extension() {
        let filter = FilterCondition::Simple {
            field: "extension".to_string(),
            operator: FilterOp::Exists,
            value: json!(null),
        };
        // File without extension — extension resolves to null
        assert!(!filter.evaluate("FileEntry", &json!({"name": "Makefile"})));
    }

    #[test]
    fn test_extension_multiple_dots() {
        let filter = FilterCondition::Simple {
            field: "extension".to_string(),
            operator: FilterOp::Eq,
            value: json!("gz"),
        };
        // rfind('.') should give "gz", not "tar.gz"
        assert!(filter.evaluate("FileEntry", &json!({"name": "archive.tar.gz"})));
    }

    #[test]
    fn test_extension_very_long() {
        let filter = FilterCondition::Simple {
            field: "extension".to_string(),
            operator: FilterOp::Exists,
            value: json!(null),
        };
        // Extension >= 10 chars is treated as not an extension
        assert!(!filter.evaluate("FileEntry", &json!({"name": "file.longextension"})));
    }

    // === Edge case: compound with empty conditions ===

    #[test]
    fn test_compound_and_empty() {
        let filter = FilterCondition::Compound {
            logic: LogicOp::And,
            conditions: vec![],
        };
        // AND with no conditions = vacuously true
        assert!(filter.evaluate("FileEntry", &json!({})));
    }

    #[test]
    fn test_compound_or_empty() {
        let filter = FilterCondition::Compound {
            logic: LogicOp::Or,
            conditions: vec![],
        };
        // OR with no conditions = false
        assert!(!filter.evaluate("FileEntry", &json!({})));
    }

    // === Edge case: contains with non-string ===

    #[test]
    fn test_contains_non_string() {
        let filter = FilterCondition::Simple {
            field: "size".to_string(),
            operator: FilterOp::Contains,
            value: json!("10"),
        };
        // size is a number, contains should return false
        assert!(!filter.evaluate("FileEntry", &json!({"name": "a", "size": 1024})));
    }

    // === Edge case: predefined filters against realistic data ===

    #[test]
    fn test_predefined_encrypted_files() {
        let filters = predefined_filters();
        let encrypted_filter = &filters
            .iter()
            .find(|(name, _, _)| *name == "Encrypted Files")
            .unwrap()
            .2;

        // EFS-encrypted file
        assert!(encrypted_filter.evaluate(
            "FileEntry",
            &json!({"name": "secret.docx", "efs_encrypted": true})
        ));
        // A signature-backed encryption detection
        assert!(encrypted_filter.evaluate(
            "ParsedRecord",
            &json!({"analysis_type": "encryption_detection", "is_encrypted": true})
        ));
        // HUNT-180: an entropy-only lead is not an encrypted file
        assert!(!encrypted_filter.evaluate(
            "ParsedRecord",
            &json!({
                "analysis_type": "encryption_detection",
                "encryption_type": "Unknown (high entropy)"
            })
        ));
        // Normal file
        assert!(!encrypted_filter.evaluate("FileEntry", &json!({"name": "readme.txt"})));
    }

    #[test]
    fn test_predefined_email_filter() {
        let filters = predefined_filters();
        let email_filter = &filters
            .iter()
            .find(|(name, _, _)| *name == "Email Messages")
            .unwrap()
            .2;

        assert!(email_filter.evaluate(
            "ParsedRecord",
            &json!({"name": "msg.eml", "analysis_type": "email"})
        ));
        assert!(email_filter.evaluate("FileEntry", &json!({"name": "inbox.mbox"})));
        assert!(email_filter.evaluate("FileEntry", &json!({"name": "outlook.MSG"})));
        assert!(!email_filter.evaluate("FileEntry", &json!({"name": "report.pdf"})));
    }

    // === JSON serialization roundtrip ===

    #[test]
    fn test_filter_json_roundtrip() {
        let filter = FilterCondition::Compound {
            logic: LogicOp::And,
            conditions: vec![
                FilterCondition::Simple {
                    field: "extension".to_string(),
                    operator: FilterOp::In,
                    value: json!(["exe", "dll"]),
                },
                FilterCondition::Not {
                    condition: Box::new(FilterCondition::Simple {
                        field: "deleted".to_string(),
                        operator: FilterOp::Eq,
                        value: json!(true),
                    }),
                },
            ],
        };

        let json_str = serde_json::to_string(&filter).unwrap();
        let deserialized: FilterCondition = serde_json::from_str(&json_str).unwrap();

        // Verify the deserialized filter works the same
        let meta = json!({"name": "app.exe", "deleted": false});
        assert_eq!(
            filter.evaluate("FileEntry", &meta),
            deserialized.evaluate("FileEntry", &meta)
        );
    }

    // === Edge case: negative numbers ===

    #[test]
    fn test_negative_number_comparison() {
        let filter = FilterCondition::Simple {
            field: "offset".to_string(),
            operator: FilterOp::Gt,
            value: json!(-100),
        };
        assert!(filter.evaluate("FileEntry", &json!({"offset": 0})));
        assert!(filter.evaluate("FileEntry", &json!({"offset": -50})));
        assert!(!filter.evaluate("FileEntry", &json!({"offset": -200})));
    }

    // === B2-024: ordering must agree with equality on case ===

    #[test]
    fn string_ordering_is_case_insensitive_like_equality() {
        let gte_lower = FilterCondition::Simple {
            field: "name".to_string(),
            operator: FilterOp::Gte,
            value: json!("m"),
        };
        let gte_upper = FilterCondition::Simple {
            field: "name".to_string(),
            operator: FilterOp::Gte,
            value: json!("M"),
        };
        // Capitalised names used to fall below every lower-case bound because
        // ASCII 'N' (0x4E) sorts before 'm' (0x6D).
        let meta = json!({"name": "Notes.txt"});
        assert!(gte_lower.evaluate("FileEntry", &meta));
        assert!(gte_upper.evaluate("FileEntry", &meta));
        assert_eq!(
            gte_lower.evaluate("FileEntry", &meta),
            gte_upper.evaluate("FileEntry", &meta),
            "the case of the bound must not change which records match"
        );
    }

    #[test]
    fn string_ordering_still_separates_distinct_names() {
        let lt = FilterCondition::Simple {
            field: "name".to_string(),
            operator: FilterOp::Lt,
            value: json!("m"),
        };
        assert!(lt.evaluate("FileEntry", &json!({"name": "Alpha.txt"})));
        assert!(!lt.evaluate("FileEntry", &json!({"name": "zeta.txt"})));
    }

    // === B2-025: extension resolution beyond `name` ===

    #[test]
    fn extension_falls_back_to_path_when_name_has_no_dot() {
        let filter = FilterCondition::Simple {
            field: "extension".to_string(),
            operator: FilterOp::Eq,
            value: json!("jpg"),
        };
        // Parsers that record only a full path used to be invisible to every
        // extension filter, so "All Graphics" looked complete while missing them.
        assert!(filter.evaluate("FileEntry", &json!({"path": "/DCIM/100APPLE/IMG_0001.JPG"})));
        assert!(filter.evaluate("FileEntry", &json!({"source_path": "C:\\Users\\a\\x.jpg"})));
    }

    #[test]
    fn extension_prefers_an_explicit_field_over_derivation() {
        let filter = FilterCondition::Simple {
            field: "extension".to_string(),
            operator: FilterOp::Eq,
            value: json!("png"),
        };
        assert!(filter.evaluate(
            "FileEntry",
            &json!({"extension": ".PNG", "name": "renamed.txt"})
        ));
    }

    #[test]
    fn extension_is_absent_rather_than_guessed() {
        let exists = FilterCondition::Simple {
            field: "extension".to_string(),
            operator: FilterOp::Exists,
            value: json!(null),
        };
        // No dot anywhere: "no extension" must stay null, never an empty string
        // that would then match an `eq ""` filter.
        assert!(!exists.evaluate("FileEntry", &json!({"name": "Makefile"})));
        assert!(!exists.evaluate("FileEntry", &json!({"path": "/etc/hosts", "name": "hosts"})));
        // A trailing dot is not an extension either.
        assert!(!exists.evaluate("FileEntry", &json!({"name": "weird."})));
    }
}
