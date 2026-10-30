//! Virtual Column system for semantic field mapping across artifact types
//!
//! Virtual columns allow unified analysis by mapping semantically similar fields
//! from different artifact types into cohesive analytical views using COALESCE logic.

use serde::{Deserialize, Serialize};

/// Defines how a virtual column maps to underlying JSON fields
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VirtualColumnDef {
    /// Unique identifier for this virtual column
    pub id: String,

    /// Display name (e.g., "Modification Time", "Resource Path")
    pub name: String,

    /// Human-readable description
    pub description: String,

    /// Data type of this column
    #[serde(rename = "type")]
    pub column_type: VirtualColumnType,

    /// Ordered list of JSON paths to try (COALESCE order)
    pub sources: Vec<VirtualColumnSource>,

    /// Whether this column should be visible by default
    pub default_visible: bool,

    /// Whether this is a built-in (immutable) column
    #[serde(default)]
    pub built_in: bool,
}

/// Type of data in a virtual column
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum VirtualColumnType {
    String,
    Integer,
    Timestamp,
    Boolean,
}

/// A single source path for a virtual column
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VirtualColumnSource {
    /// JSON path (e.g., "$.filename", "$.modified_time")
    pub path: String,

    /// Optional filter by artifact types (e.g., ["ntfs.mft", "prefetch"]).
    /// Empty list means all artifact types.
    ///
    /// **Superseded by [`Self::source_modules`], and read by nothing.** The
    /// vocabulary here has no counterpart in a timeline event: an event carries
    /// `source_module` (`"plugin.windows.registry_parser"`) and, for MFT rows
    /// only, a `$.artifact_type` of `FILE` or `DIR`. Neither is `"registry"` or
    /// `"ntfs.mft"`, so an equality gate on this field would reject every typed
    /// source and blank the column, and substring matching does not save it —
    /// `"plugin.browsers.history_parser"` does not contain `"browser_history"`.
    ///
    /// Kept because custom columns are stored with it (`sources_json` in the
    /// `virtual_columns` table). Reinterpreting the field would silently
    /// re-gate somebody's saved column against a vocabulary they never wrote.
    #[serde(default)]
    pub artifact_types: Vec<String>,

    /// Restrict this source to events from these modules, by `source_module`.
    ///
    /// Empty means "any module", which is what a generic fallback like
    /// `$.path` wants. A module-specific source names its emitters, so a source
    /// earlier in the list cannot claim an event it was never about — the
    /// reason a registry event must not take its resource path from
    /// `$.filename`.
    ///
    /// Matched by equality against the full module id, because that is what the
    /// event actually carries.
    #[serde(default)]
    pub source_modules: Vec<String>,
}

impl VirtualColumnSource {
    /// Whether this source may supply a value for an event from `source_module`.
    pub fn applies_to(&self, source_module: &str) -> bool {
        self.source_modules.is_empty()
            || self
                .source_modules
                .iter()
                .any(|allowed| allowed == source_module)
    }
}

impl VirtualColumnDef {
    /// Generate SQL COALESCE expression for this virtual column
    ///
    /// A module-restricted source becomes a `CASE WHEN source_module IN (…)`,
    /// so precedence here matches what the client resolves. Without it the
    /// COALESCE takes the first non-null path in declaration order regardless
    /// of which module produced the row, and a source written for one artifact
    /// answers for another.
    ///
    /// Nothing in the tree calls this today — the client resolves the column
    /// from `dynamic_fields`. It is kept correct rather than left as a trap for
    /// whoever wires it up.
    ///
    /// # Arguments
    /// * `table_alias` - Optional table alias (e.g., "te")
    /// * `default_value` - Default value if all paths are null
    pub fn to_sql_coalesce(&self, table_alias: Option<&str>, default_value: &str) -> String {
        let (full_details, source_module) = if let Some(alias) = table_alias {
            (
                format!("{}.full_details", alias),
                format!("{}.source_module", alias),
            )
        } else {
            ("full_details".to_string(), "source_module".to_string())
        };

        let extracts: Vec<String> = self
            .sources
            .iter()
            .filter(|source| {
                // Runtime safety: reject paths with characters that could break out of SQL string
                source
                    .path
                    .chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, '$' | '.' | '_' | '[' | ']'))
            })
            .filter(|source| {
                // A module id carrying a quote cannot be interpolated safely,
                // and dropping the whole source is the safe reading: it makes
                // the column fall through to the next one rather than emitting
                // SQL nobody checked.
                source.source_modules.iter().all(|m| {
                    m.chars()
                        .all(|c| c.is_alphanumeric() || c == '.' || c == '_')
                })
            })
            .map(|source| {
                let extract = format!("json_extract({}, '{}')", full_details, source.path);
                if source.source_modules.is_empty() {
                    return extract;
                }
                let allowed = source
                    .source_modules
                    .iter()
                    .map(|m| format!("'{m}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("CASE WHEN {source_module} IN ({allowed}) THEN {extract} END")
            })
            .collect();

        // The default is a SQL string literal: double any single quote so a
        // value cannot close it and append SQL. (NUL bytes are not stripped:
        // this builds text for a caller that binds nothing, and the defaults in
        // use are fixed strings.)
        let default_literal = format!("'{}'", default_value.replace('\'', "''"));
        if extracts.is_empty() {
            return default_literal;
        }

        let mut coalesce_args = extracts;
        coalesce_args.push(default_literal);

        format!("COALESCE({})", coalesce_args.join(", "))
    }

    /// Get column alias for SQL (lowercase, underscored)
    pub fn sql_alias(&self) -> String {
        self.name.to_lowercase().replace(' ', "_")
    }

    /// Validate virtual column definition
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Virtual column name cannot be empty".to_string());
        }

        if self.sources.is_empty() {
            return Err("Virtual column must have at least one source path".to_string());
        }

        // Validate JSON paths - must be safe for SQL interpolation
        for source in &self.sources {
            if !source.path.starts_with('$') {
                return Err(format!(
                    "Invalid JSON path '{}': must start with $",
                    source.path
                ));
            }
            // Prevent SQL injection: only allow alphanumeric chars, dots, underscores, brackets, and $
            if !source
                .path
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '$' | '.' | '_' | '[' | ']'))
            {
                return Err(format!(
                    "Invalid JSON path '{}': contains disallowed characters (only alphanumeric, $, ., _, [, ] permitted)",
                    source.path
                ));
            }
        }

        Ok(())
    }
}

/// Collection of virtual column definitions for a case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualColumnSet {
    /// List of virtual column definitions
    pub virtual_columns: Vec<VirtualColumnDef>,
}

impl VirtualColumnSet {
    /// Load default built-in virtual columns
    pub fn default_columns() -> Self {
        VirtualColumnSet {
            virtual_columns: vec![
                VirtualColumnDef {
                    id: "vc_resource_path".to_string(),
                    name: "Resource Path".to_string(),
                    description: "File path, registry key, URL, or resource identifier".to_string(),
                    column_type: VirtualColumnType::String,
                    // Ordered module-specific first, then generic fallbacks.
                    // The field names come from what the parsers emit into a
                    // timeline event's `full_details`, checked against 185,904
                    // events from the CFReDS Hacking Case image — not from the
                    // names the column previously guessed at.
                    //
                    // Those guesses were why the column was blank for 47% of
                    // that case: registry events carry `key_path` and the
                    // column looked for `registry_key`; lnk carries
                    // `target_path`; prefetch carries `executable_name`. Only
                    // MFT (`filename`) and shellbags (`path`) ever resolved.
                    sources: vec![
                        VirtualColumnSource {
                            path: "$.key_path".to_string(),
                            artifact_types: vec![],
                            source_modules: vec!["plugin.windows.registry_parser".to_string()],
                        },
                        VirtualColumnSource {
                            path: "$.target_path".to_string(),
                            artifact_types: vec![],
                            source_modules: vec!["plugin.windows.lnk_parser".to_string()],
                        },
                        VirtualColumnSource {
                            path: "$.executable_name".to_string(),
                            artifact_types: vec![],
                            source_modules: vec!["plugin.windows.prefetch_parser".to_string()],
                        },
                        VirtualColumnSource {
                            path: "$.url".to_string(),
                            artifact_types: vec![],
                            source_modules: vec!["plugin.browsers.history_parser".to_string()],
                        },
                        // `registry_key` is emitted by nothing in this tree. It
                        // stays, gated, so a case whose records do carry it is
                        // not silently worse off than before — and gated so it
                        // cannot claim an event from another module.
                        VirtualColumnSource {
                            path: "$.registry_key".to_string(),
                            artifact_types: vec![],
                            source_modules: vec!["plugin.windows.registry_parser".to_string()],
                        },
                        // Named emitters rather than left open: the guarantee
                        // this column has to make is that a registry event
                        // never takes its path from a filename.
                        VirtualColumnSource {
                            path: "$.filename".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![
                                "plugin.ntfs.mft_parser".to_string(),
                                "plugin.ntfs.usnjrnl_parser".to_string(),
                                "plugin.email.parser".to_string(),
                            ],
                        },
                        // Generic fallbacks, in decreasing specificity. A
                        // module this list has never heard of still resolves
                        // something rather than rendering blank.
                        VirtualColumnSource {
                            path: "$.path".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                        VirtualColumnSource {
                            path: "$.name".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                    ],
                    default_visible: true,
                    built_in: true,
                },
                VirtualColumnDef {
                    id: "vc_file_size".to_string(),
                    name: "File Size".to_string(),
                    description: "Size in bytes".to_string(),
                    column_type: VirtualColumnType::Integer,
                    sources: vec![
                        VirtualColumnSource {
                            path: "$.file_size".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                        VirtualColumnSource {
                            path: "$.size".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                        VirtualColumnSource {
                            // Ungated on purpose: `artifact_types` is read by
                            // nothing, so naming one here would advertise a
                            // restriction that does not exist.
                            path: "$.allocated_size".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                    ],
                    default_visible: false,
                    built_in: true,
                },
                VirtualColumnDef {
                    id: "vc_user".to_string(),
                    name: "User".to_string(),
                    description: "User account associated with this activity".to_string(),
                    column_type: VirtualColumnType::String,
                    sources: vec![
                        VirtualColumnSource {
                            path: "$.user".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                        VirtualColumnSource {
                            path: "$.username".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                        VirtualColumnSource {
                            path: "$.account".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                    ],
                    default_visible: false,
                    built_in: true,
                },
                VirtualColumnDef {
                    id: "vc_process".to_string(),
                    name: "Process".to_string(),
                    description: "Process name or identifier".to_string(),
                    column_type: VirtualColumnType::String,
                    sources: vec![
                        VirtualColumnSource {
                            path: "$.process_name".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                        VirtualColumnSource {
                            path: "$.process".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                        VirtualColumnSource {
                            // Ungated on purpose, as `$.allocated_size` above.
                            path: "$.executable".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                    ],
                    default_visible: false,
                    built_in: true,
                },
                VirtualColumnDef {
                    id: "vc_hash".to_string(),
                    name: "Hash".to_string(),
                    description: "File hash (MD5, SHA1, SHA256)".to_string(),
                    column_type: VirtualColumnType::String,
                    sources: vec![
                        VirtualColumnSource {
                            path: "$.sha256".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                        VirtualColumnSource {
                            path: "$.sha1".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                        VirtualColumnSource {
                            path: "$.md5".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                        VirtualColumnSource {
                            path: "$.hash".to_string(),
                            artifact_types: vec![],
                            source_modules: vec![],
                        },
                    ],
                    default_visible: false,
                    built_in: true,
                },
            ],
        }
    }

    /// Find a virtual column by ID
    pub fn find_by_id(&self, id: &str) -> Option<&VirtualColumnDef> {
        self.virtual_columns.iter().find(|vc| vc.id == id)
    }

    /// Get all visible virtual columns
    pub fn visible_columns(&self) -> Vec<&VirtualColumnDef> {
        self.virtual_columns
            .iter()
            .filter(|vc| vc.default_visible)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_value_cannot_close_its_string_literal() {
        let vc = VirtualColumnDef {
            id: "t".into(),
            name: "T".into(),
            description: "t".into(),
            column_type: VirtualColumnType::String,
            sources: vec![VirtualColumnSource {
                path: "$.a".into(),
                artifact_types: vec![],
                source_modules: vec![],
            }],
            default_visible: false,
            built_in: false,
        };
        let sql = vc.to_sql_coalesce(None, "x') FROM artifacts; --");
        assert!(sql.ends_with(", 'x'') FROM artifacts; --')"), "{sql}");
        let none = VirtualColumnDef {
            sources: vec![],
            ..vc
        };
        assert_eq!(none.to_sql_coalesce(None, "it's"), "'it''s'");
    }

    #[test]
    fn built_in_sources_do_not_advertise_the_inert_artifact_type_gate() {
        for column in VirtualColumnSet::default_columns().virtual_columns {
            for source in &column.sources {
                assert!(
                    source.artifact_types.is_empty(),
                    "{} {}: artifact_types is read by nothing, so a built-in must not claim a \
                     restriction through it",
                    column.name,
                    source.path
                );
            }
        }
    }

    #[test]
    fn test_sql_coalesce_generation() {
        let vc = VirtualColumnDef {
            id: "test".to_string(),
            name: "Resource Path".to_string(),
            description: "Test".to_string(),
            column_type: VirtualColumnType::String,
            sources: vec![
                VirtualColumnSource {
                    path: "$.filename".to_string(),
                    artifact_types: vec![],
                    source_modules: vec![],
                },
                VirtualColumnSource {
                    path: "$.path".to_string(),
                    artifact_types: vec![],
                    source_modules: vec![],
                },
            ],
            default_visible: true,
            built_in: true,
        };

        let sql = vc.to_sql_coalesce(Some("te"), "-");
        assert!(sql.contains("COALESCE"));
        assert!(sql.contains("json_extract(te.full_details, '$.filename')"));
        assert!(sql.contains("json_extract(te.full_details, '$.path')"));
        assert!(sql.contains("'-'"));
    }

    #[test]
    fn test_sql_alias() {
        let vc = VirtualColumnDef {
            id: "test".to_string(),
            name: "Resource Path".to_string(),
            description: "Test".to_string(),
            column_type: VirtualColumnType::String,
            sources: vec![],
            default_visible: true,
            built_in: true,
        };

        assert_eq!(vc.sql_alias(), "resource_path");
    }

    #[test]
    fn test_validation() {
        let mut vc = VirtualColumnDef {
            id: "test".to_string(),
            name: "Test".to_string(),
            description: "Test".to_string(),
            column_type: VirtualColumnType::String,
            sources: vec![VirtualColumnSource {
                path: "$.test".to_string(),
                artifact_types: vec![],
                source_modules: vec![],
            }],
            default_visible: true,
            built_in: false,
        };

        assert!(vc.validate().is_ok());

        // Test empty name
        vc.name = "".to_string();
        assert!(vc.validate().is_err());

        // Test no sources
        vc.name = "Test".to_string();
        vc.sources = vec![];
        assert!(vc.validate().is_err());

        // Test invalid JSON path (no $ prefix)
        vc.sources = vec![VirtualColumnSource {
            path: "filename".to_string(),
            artifact_types: vec![],
            source_modules: vec![],
        }];
        assert!(vc.validate().is_err());

        // Test SQL injection attempt in JSON path
        vc.sources = vec![VirtualColumnSource {
            path: "$'; DROP TABLE artifacts; --".to_string(),
            artifact_types: vec![],
            source_modules: vec![],
        }];
        assert!(vc.validate().is_err());

        // Test valid JSON path with brackets
        vc.sources = vec![VirtualColumnSource {
            path: "$.items[0].name".to_string(),
            artifact_types: vec![],
            source_modules: vec![],
        }];
        assert!(vc.validate().is_ok());
    }

    #[test]
    fn test_default_columns() {
        let columns = VirtualColumnSet::default_columns();
        assert!(columns.virtual_columns.len() >= 5);

        // Verify Resource Path column exists
        let resource_path = columns.find_by_id("vc_resource_path");
        assert!(resource_path.is_some());
        assert_eq!(resource_path.unwrap().name, "Resource Path");
    }
}
