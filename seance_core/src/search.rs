//! Advanced search query parser for timeline filtering
//!
//! Supports the following syntax:
//! - Basic: `mimikatz` → Contains "mimikatz" (case-insensitive)
//! - Phrase: `"lateral movement"` → Exact phrase match
//! - Required: `+mimikatz +lsass` → Must contain BOTH
//! - Exclude: `mimikatz -false_positive` → Contains "mimikatz" but NOT "false_positive"
//! - Column: `EventType:Created` → event_type column contains "Created"
//! - Combined: `+EventType:Modified +Resource:*.dll -Source:prefetch`

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchQuery {
    pub terms: Vec<SearchTerm>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SearchTerm {
    /// Contains text (OR logic if multiple, case-insensitive)
    Contains { text: String, required: bool },
    /// Exclude text (NOT logic)
    Exclude { text: String },
    /// Exact phrase match (case-insensitive)
    ExactPhrase { text: String, required: bool },
    /// Column-specific filter (column:value, supports wildcards)
    ColumnFilter {
        column: String,
        value: String,
        required: bool,
    },
}

impl SearchQuery {
    /// Parse a search query string into structured terms
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() {
            return Ok(SearchQuery { terms: vec![] });
        }

        let mut terms = Vec::new();
        let mut chars = input.chars().peekable();
        let mut current_pos = 0;

        while chars.peek().is_some() {
            // Skip whitespace
            while chars.peek() == Some(&' ') {
                chars.next();
                current_pos += 1;
            }

            if chars.peek().is_none() {
                break;
            }

            // Check for modifiers
            let required = if chars.peek() == Some(&'+') {
                chars.next();
                current_pos += 1;
                true
            } else {
                false
            };

            let exclude = if chars.peek() == Some(&'-') {
                chars.next();
                current_pos += 1;
                true
            } else {
                false
            };

            // Parse term
            if chars.peek() == Some(&'"') {
                // Exact phrase
                chars.next(); // consume opening quote
                current_pos += 1;

                let mut phrase = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch == '"' {
                        chars.next(); // consume closing quote
                        current_pos += 1;
                        break;
                    }
                    phrase.push(ch);
                    chars.next();
                    current_pos += 1;
                }

                if phrase.is_empty() {
                    return Err(format!("Empty phrase at position {}", current_pos));
                }

                if exclude {
                    return Err("Cannot exclude exact phrases (combine -word instead)".to_string());
                }

                terms.push(SearchTerm::ExactPhrase {
                    text: phrase,
                    required,
                });
            } else {
                // Word or column:value
                let mut word = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch == ' ' || ch == '"' {
                        break;
                    }
                    word.push(ch);
                    chars.next();
                    current_pos += 1;
                }

                if word.is_empty() {
                    continue;
                }

                // A `name:value` term is a column filter ONLY when `name` is a
                // column we know how to map. Anything else keeps its colon and
                // is searched literally -- a Windows path or drive letter
                // (`C:\Users\alice`) is a search term, not a filter on a column
                // called `C` (BUG-247).
                let column_filter = word.find(':').and_then(|colon_pos| {
                    let column = &word[..colon_pos];
                    Self::resolve_column(column)
                        .map(|_| (column.to_string(), word[colon_pos + 1..].to_string()))
                });

                if let Some((column, value)) = column_filter {
                    if value.is_empty() {
                        return Err(format!(
                            "Invalid column filter '{}' at position {}",
                            word, current_pos
                        ));
                    }

                    if exclude {
                        return Err(format!("Column filters cannot be excluded (use -ColumnName:value syntax not supported, use different value instead) at position {}", current_pos));
                    }

                    terms.push(SearchTerm::ColumnFilter {
                        column,
                        value,
                        required,
                    });
                } else {
                    // Regular word
                    if exclude {
                        terms.push(SearchTerm::Exclude { text: word });
                    } else {
                        terms.push(SearchTerm::Contains {
                            text: word,
                            required,
                        });
                    }
                }
            }
        }

        Ok(SearchQuery { terms })
    }

    /// Build SQL WHERE clause from parsed query
    /// Returns (where_clause, params) tuple
    /// If table_prefix is provided (e.g., "te"), columns will be prefixed like "te.full_details"
    pub fn to_sql(&self) -> (String, Vec<String>) {
        self.to_sql_with_prefix(None)
    }

    /// Build SQL WHERE clause with optional table prefix
    pub fn to_sql_with_prefix(&self, table_prefix: Option<&str>) -> (String, Vec<String>) {
        if self.terms.is_empty() {
            return (String::new(), vec![]);
        }

        let prefix = table_prefix.map(|p| format!("{}.", p)).unwrap_or_default();

        // Build each term's SQL fragment together with its bound params so the
        // two can be reordered in lockstep below. The final clause emits
        // required conditions before optional ones; keeping params in raw term
        // order while the conditions are reordered would bind every placeholder
        // to the wrong value whenever an optional term precedes a required one.
        let mut built: Vec<(String, Vec<String>)> = Vec::new();

        for term in &self.terms {
            match term {
                SearchTerm::Contains { text, required: _ } => {
                    // Search full_details, short_desc AND timestamp_desc — the
                    // same three columns the simple LIKE path searches. Any
                    // query containing `+`, `-`, `"` or `:` routes here, which
                    // includes everyday terms: hyphenated words, Windows paths,
                    // date fragments. Searching only two of the three columns
                    // made an event whose sole match is its timestamp
                    // description read as "no such activity" for those queries
                    // while an equivalent plain query found it (B5-011).
                    let condition = format!(
                        "({}full_details LIKE ? ESCAPE '\\' OR {}short_desc LIKE ? ESCAPE '\\' \
                         OR {}timestamp_desc LIKE ? ESCAPE '\\')",
                        prefix, prefix, prefix
                    );
                    let pattern = format!("%{}%", escape_like(text));
                    built.push((condition, vec![pattern.clone(), pattern.clone(), pattern]));
                }
                SearchTerm::Exclude { text } => {
                    let condition = format!(
                        "({}full_details NOT LIKE ? ESCAPE '\\' AND {}short_desc NOT LIKE ? ESCAPE '\\' \
                         AND {}timestamp_desc NOT LIKE ? ESCAPE '\\')",
                        prefix, prefix, prefix
                    );
                    let pattern = format!("%{}%", escape_like(text));
                    built.push((condition, vec![pattern.clone(), pattern.clone(), pattern]));
                }
                SearchTerm::ExactPhrase { text, required: _ } => {
                    // Exact phrase match (case-insensitive via LIKE)
                    let condition = format!(
                        "({}full_details LIKE ? ESCAPE '\\' OR {}short_desc LIKE ? ESCAPE '\\' \
                         OR {}timestamp_desc LIKE ? ESCAPE '\\')",
                        prefix, prefix, prefix
                    );
                    let pattern = format!("%{}%", escape_like(text));
                    built.push((condition, vec![pattern.clone(), pattern.clone(), pattern]));
                }
                SearchTerm::ColumnFilter {
                    column,
                    value,
                    required: _,
                } => {
                    // Map friendly column names to database columns
                    let db_column = Self::map_column_name(column);

                    // Escape the literal text first, then turn the user's `*`
                    // into the SQL wildcard: `*` is the ONLY wildcard this
                    // syntax offers, so a literal `_`/`%` in the value must not
                    // silently widen the filter (BUG-246). Escaping never emits
                    // a `*`, so the substitution below only touches the user's.
                    let escaped = escape_like(value);
                    let pattern = if value.contains('*') {
                        format!("%{}%", escaped.replace('*', "%"))
                    } else {
                        format!("%{}%", escaped)
                    };
                    built.push((
                        format!("{}{} LIKE ? ESCAPE '\\'", prefix, db_column),
                        vec![pattern],
                    ));
                }
            }
        }

        // Separate required and optional terms, carrying each condition's params
        // with it so placeholder/param order stays aligned after reordering.
        let mut required_conditions = Vec::new();
        let mut optional_conditions = Vec::new();
        let mut required_params: Vec<String> = Vec::new();
        let mut optional_params: Vec<String> = Vec::new();

        for (term, (condition, term_params)) in self.terms.iter().zip(built) {
            match term {
                SearchTerm::Contains { required: true, .. }
                | SearchTerm::ExactPhrase { required: true, .. }
                | SearchTerm::ColumnFilter { required: true, .. }
                | SearchTerm::Exclude { .. } => {
                    required_conditions.push(condition);
                    required_params.extend(term_params);
                }
                _ => {
                    optional_conditions.push(condition);
                    optional_params.extend(term_params);
                }
            }
        }

        // Build final WHERE clause
        let mut where_parts = Vec::new();

        if !required_conditions.is_empty() {
            where_parts.push(required_conditions.join(" AND "));
        }

        if !optional_conditions.is_empty() {
            where_parts.push(format!("({})", optional_conditions.join(" OR ")));
        }

        let where_clause = if where_parts.is_empty() {
            String::new()
        } else {
            where_parts.join(" AND ")
        };

        // Params follow the same required-then-optional order as the clauses.
        let mut params = required_params;
        params.extend(optional_params);

        (where_clause, params)
    }

    /// Map a user-friendly column name to its database column, or `None` when
    /// the name is not one this syntax recognises. `None` means "this is not a
    /// column filter at all" — the caller keeps the term literal.
    fn resolve_column(column: &str) -> Option<&'static str> {
        Some(match column.to_lowercase().as_str() {
            "eventtype" | "event_type" | "type" => "timestamp_desc",
            "source" | "module" => "source_module",
            "description" | "desc" => "short_desc",
            // `resource` is extracted from the JSON blob, so it is searched
            // through full_details.
            "resource" | "filename" | "file" => "full_details",
            _ => return None,
        })
    }

    /// Database column for a parsed `ColumnFilter`. Parsing only produces known
    /// columns, but a `SearchQuery` can also be deserialized, so an unknown name
    /// still falls back to the JSON blob rather than building invalid SQL.
    fn map_column_name(column: &str) -> String {
        Self::resolve_column(column)
            .unwrap_or("full_details")
            .to_string()
    }
}

/// Escape the LIKE metacharacters (`%`, `_`) and the escape character itself so
/// a bound pattern matches the user's text literally. Every LIKE this module
/// builds is emitted with `ESCAPE '\'`; without this, a forensic name like
/// `report_final` silently matches `reportxfinal` too (BUG-246). Mirrors the
/// simple-search path in `seance_db`.
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_word() {
        let query = SearchQuery::parse("mimikatz").unwrap();
        assert_eq!(query.terms.len(), 1);
        assert!(matches!(
            &query.terms[0],
            SearchTerm::Contains { text, required: false } if text == "mimikatz"
        ));
    }

    #[test]
    fn test_parse_multiple_words() {
        let query = SearchQuery::parse("mimikatz lsass").unwrap();
        assert_eq!(query.terms.len(), 2);
    }

    #[test]
    fn test_parse_required_word() {
        let query = SearchQuery::parse("+mimikatz").unwrap();
        assert_eq!(query.terms.len(), 1);
        assert!(matches!(
            &query.terms[0],
            SearchTerm::Contains { text, required: true } if text == "mimikatz"
        ));
    }

    #[test]
    fn test_parse_excluded_word() {
        let query = SearchQuery::parse("-false_positive").unwrap();
        assert_eq!(query.terms.len(), 1);
        assert!(matches!(
            &query.terms[0],
            SearchTerm::Exclude { text } if text == "false_positive"
        ));
    }

    #[test]
    fn test_parse_exact_phrase() {
        let query = SearchQuery::parse("\"lateral movement\"").unwrap();
        assert_eq!(query.terms.len(), 1);
        assert!(matches!(
            &query.terms[0],
            SearchTerm::ExactPhrase { text, required: false } if text == "lateral movement"
        ));
    }

    #[test]
    fn test_parse_required_exact_phrase() {
        let query = SearchQuery::parse("+\"privilege escalation\"").unwrap();
        assert_eq!(query.terms.len(), 1);
        assert!(matches!(
            &query.terms[0],
            SearchTerm::ExactPhrase { text, required: true } if text == "privilege escalation"
        ));
    }

    #[test]
    fn test_parse_column_filter() {
        let query = SearchQuery::parse("EventType:Created").unwrap();
        assert_eq!(query.terms.len(), 1);
        assert!(matches!(
            &query.terms[0],
            SearchTerm::ColumnFilter { column, value, required: false }
            if column == "EventType" && value == "Created"
        ));
    }

    #[test]
    fn test_parse_column_filter_with_wildcard() {
        let query = SearchQuery::parse("Resource:*.exe").unwrap();
        assert_eq!(query.terms.len(), 1);
        assert!(matches!(
            &query.terms[0],
            SearchTerm::ColumnFilter { column, value, required: false }
            if column == "Resource" && value == "*.exe"
        ));
    }

    #[test]
    fn test_parse_complex_query() {
        let query = SearchQuery::parse("+EventType:Modified +Resource:*.dll -prefetch").unwrap();
        assert_eq!(query.terms.len(), 3);

        assert!(matches!(
            &query.terms[0],
            SearchTerm::ColumnFilter { column, value, required: true }
            if column == "EventType" && value == "Modified"
        ));

        assert!(matches!(
            &query.terms[1],
            SearchTerm::ColumnFilter { column, value, required: true }
            if column == "Resource" && value == "*.dll"
        ));

        assert!(matches!(
            &query.terms[2],
            SearchTerm::Exclude { text } if text == "prefetch"
        ));
    }

    #[test]
    fn test_parse_mixed_query() {
        let query = SearchQuery::parse("+mimikatz +lsass -false_positive").unwrap();
        assert_eq!(query.terms.len(), 3);

        assert!(matches!(
            &query.terms[0],
            SearchTerm::Contains { text, required: true } if text == "mimikatz"
        ));

        assert!(matches!(
            &query.terms[1],
            SearchTerm::Contains { text, required: true } if text == "lsass"
        ));

        assert!(matches!(
            &query.terms[2],
            SearchTerm::Exclude { text } if text == "false_positive"
        ));
    }

    #[test]
    fn test_to_sql_simple() {
        let query = SearchQuery::parse("mimikatz").unwrap();
        let (sql, params) = query.to_sql();

        assert!(sql.contains("full_details LIKE ?"));
        assert!(sql.contains("short_desc LIKE ?"));
        // B5-011: the advanced path must cover the same three columns the
        // simple LIKE path does, timestamp_desc included.
        assert!(sql.contains("timestamp_desc LIKE ?"), "{sql}");
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], "%mimikatz%");
    }

    #[test]
    fn test_to_sql_required_and_excluded() {
        let query = SearchQuery::parse("+mimikatz -false_positive").unwrap();
        let (sql, params) = query.to_sql();

        assert!(sql.contains("AND"));
        assert!(sql.contains("NOT LIKE"));
        assert!(sql.contains("timestamp_desc NOT LIKE ?"), "{sql}");
        assert_eq!(params.len(), 6); // 3 columns for mimikatz, 3 for false_positive
    }

    #[test]
    fn test_to_sql_param_alignment_optional_before_required() {
        // Regression: an optional term before a required one must not misalign
        // bound params with their placeholders. Required clauses are emitted
        // first, so their params must lead in the same order.
        let query = SearchQuery::parse("foo +bar").unwrap();
        let (where_clause, params) = query.to_sql();

        assert_eq!(
            params,
            vec!["%bar%", "%bar%", "%bar%", "%foo%", "%foo%", "%foo%"]
        );
        // Required "bar" clause is ANDed ahead of the optional "foo" group.
        assert!(where_clause.contains(") AND (("), "got: {where_clause}");
    }

    #[test]
    fn test_empty_query() {
        let query = SearchQuery::parse("").unwrap();
        assert_eq!(query.terms.len(), 0);

        let (sql, params) = query.to_sql();
        assert!(sql.is_empty());
        assert!(params.is_empty());
    }

    #[test]
    fn test_error_empty_phrase() {
        let result = SearchQuery::parse("\"\"");
        assert!(result.is_err());
    }

    // ── BUG-246: LIKE metacharacters must be escaped ────────────────────────

    #[test]
    fn like_metacharacters_are_escaped_and_declared() {
        // `_` is a single-char LIKE wildcard: unescaped, `report_final` also
        // matches `reportxfinal`. Every LIKE must carry ESCAPE '\'.
        let query = SearchQuery::parse("+report_final -100%").unwrap();
        let (sql, params) = query.to_sql();

        assert!(
            !sql.contains("LIKE ?)") && !sql.contains("LIKE ? OR") && !sql.contains("LIKE ? AND"),
            "every LIKE must declare its escape character: {sql}"
        );
        assert_eq!(sql.matches("ESCAPE '\\'").count(), 6, "sql: {sql}");
        assert!(
            params.contains(&"%report\\_final%".to_string()),
            "{params:?}"
        );
        assert!(params.contains(&"%100\\%%".to_string()), "{params:?}");
    }

    #[test]
    fn column_filter_escapes_literals_but_keeps_star_wildcard() {
        let query = SearchQuery::parse("EventType:a_b*c").unwrap();
        let (sql, params) = query.to_sql();
        assert!(sql.contains("timestamp_desc LIKE ? ESCAPE '\\'"), "{sql}");
        // `_` literal (escaped), `*` still the user-facing wildcard.
        assert_eq!(params, vec!["%a\\_b%c%".to_string()]);
    }

    #[test]
    fn exact_phrase_escapes_metacharacters() {
        let query = SearchQuery::parse("\"lateral_movement\"").unwrap();
        let (_, params) = query.to_sql();
        assert_eq!(
            params,
            vec!["%lateral\\_movement%".to_string(); 3],
            "phrase search must match the underscore literally"
        );
    }

    // ── BUG-247: `:` only means "column filter" for a known column ──────────

    #[test]
    fn windows_path_is_a_literal_term_not_a_column_filter() {
        let query = SearchQuery::parse("C:\\Users\\alice").unwrap();
        assert_eq!(query.terms.len(), 1);
        assert!(
            matches!(
                &query.terms[0],
                SearchTerm::Contains { text, required: false } if text == "C:\\Users\\alice"
            ),
            "got: {:?}",
            query.terms
        );

        // …and it searches both text columns, like simple search does.
        let (sql, params) = query.to_sql();
        assert!(sql.contains("full_details LIKE ?"), "{sql}");
        assert!(sql.contains("short_desc LIKE ?"), "{sql}");
        assert!(sql.contains("timestamp_desc LIKE ?"), "{sql}");
        assert_eq!(params, vec!["%C:\\\\Users\\\\alice%".to_string(); 3]);
    }

    #[test]
    fn unknown_column_prefix_stays_literal() {
        // `notacolumn` is not mappable, so the whole token is the search text.
        let query = SearchQuery::parse("notacolumn:value").unwrap();
        assert!(matches!(
            &query.terms[0],
            SearchTerm::Contains { text, .. } if text == "notacolumn:value"
        ));
    }

    #[test]
    fn excluded_windows_path_stays_a_literal_exclusion() {
        // A leading '-' with a colon used to hit the "cannot exclude a column
        // filter" error; it is now an ordinary exclusion.
        let query = SearchQuery::parse("-D:\\temp").unwrap();
        assert!(matches!(
            &query.terms[0],
            SearchTerm::Exclude { text } if text == "D:\\temp"
        ));
    }

    #[test]
    fn known_column_filter_still_parses() {
        // The recognised names must keep working exactly as before.
        for input in ["EventType:Created", "Source:prefetch", "file:notes.txt"] {
            let query = SearchQuery::parse(input).unwrap();
            assert!(
                matches!(&query.terms[0], SearchTerm::ColumnFilter { .. }),
                "{input} should still be a column filter"
            );
        }
        // A known column with no value is still a user error.
        assert!(SearchQuery::parse("EventType:").is_err());
    }
}
