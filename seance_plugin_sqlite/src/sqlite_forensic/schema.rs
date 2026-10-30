//! Schema recovery from `sqlite_master` records.
//!
//! Ported from the reference `internal/schema/schema.go` and
//! `internal/schema/recovery.go`: CREATE TABLE column extraction, column-count
//! inference from orphaned records, and placeholder column generation.

use super::record::Value;

/// A recovered schema object (table, index, view, or trigger).
#[derive(Debug, Clone)]
pub struct SchemaEntry {
    pub obj_type: String,
    pub name: String,
    pub tbl_name: String,
    pub root_page: i64,
    pub sql: String,
    pub columns: Vec<String>,
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::Text(s) => s.clone(),
        Value::Blob(b) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    }
}

fn value_to_int(v: &Value) -> i64 {
    match v {
        Value::Int(n) => *n,
        Value::Float(f) => *f as i64,
        _ => 0,
    }
}

/// Interprets a decoded `sqlite_master` row (`[type, name, tbl_name, rootpage,
/// sql]`) into a [`SchemaEntry`]. Returns `None` for rows too short to be usable.
pub fn entry_from_master_row(values: &[Value]) -> Option<SchemaEntry> {
    if values.len() < 5 {
        return None;
    }
    let obj_type = value_to_string(&values[0]);
    let name = value_to_string(&values[1]);
    let tbl_name = value_to_string(&values[2]);
    let root_page = value_to_int(&values[3]);
    let sql = value_to_string(&values[4]);
    if name.is_empty() {
        return None;
    }
    let columns = if obj_type.eq_ignore_ascii_case("table") {
        parse_create_table_sql(&sql)
    } else {
        Vec::new()
    };
    Some(SchemaEntry {
        obj_type,
        name,
        tbl_name,
        root_page,
        sql,
        columns,
    })
}

/// Extracts column names from a `CREATE TABLE ... (col defs)` statement.
/// Constraint clauses (PRIMARY/UNIQUE/FOREIGN/CHECK/CONSTRAINT) are skipped.
pub fn parse_create_table_sql(sql: &str) -> Vec<String> {
    if sql.is_empty() {
        return Vec::new();
    }
    let lower = sql.to_lowercase();
    if !lower.contains("create") || !lower.contains("table") {
        return Vec::new();
    }
    let start = match sql.find('(') {
        Some(i) => i,
        None => return Vec::new(),
    };
    let mut depth = 0i32;
    let mut end = None;
    for (i, ch) in sql.char_indices().skip(start) {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = match end {
        Some(e) if e > start + 1 => e,
        _ => return Vec::new(),
    };
    let definition = &sql[start + 1..end];
    let mut columns = Vec::new();
    for segment in split_columns(definition) {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }
        if is_table_constraint(&trimmed.to_lowercase()) {
            continue;
        }
        if let Some(first) = trimmed.split_whitespace().next() {
            let name = first.trim_matches(|c| c == '`' || c == '"' || c == '[' || c == ']');
            if !name.is_empty() {
                columns.push(name.to_string());
            }
        }
    }
    columns
}

/// Whether a lower-cased definition segment is a table constraint rather than
/// a column.
///
/// A prefix test is wrong: `checksum`, `unique_id` and `primary_owner` are
/// ordinary column names that begin with a constraint keyword, and dropping one
/// shifts every later column of every recovered row by one. Google Drive's
/// `cloud_entry` has a `checksum` column (NIST CFReDS Data Leakage image,
/// `VALIDATION.md` `LEAK-2`). The keyword has to be the whole first word, and be
/// followed by what its constraint form requires.
fn is_table_constraint(lower_seg: &str) -> bool {
    let mut words = lower_seg.split_whitespace();
    let first = words.next().unwrap_or("");
    // `UNIQUE(a)` and `CHECK(a)` carry no space before the parenthesis.
    let (head, glued_paren) = match first.find('(') {
        Some(i) => (&first[..i], true),
        None => (first, false),
    };
    let paren_follows = glued_paren
        || words
            .clone()
            .next()
            .map(|w| w.starts_with('('))
            .unwrap_or(false);
    match head {
        // `CONSTRAINT name ...` always names the constraint that follows.
        "constraint" => !glued_paren && words.next().is_some(),
        "primary" | "foreign" => {
            // `PRIMARY KEY (..)` / `FOREIGN KEY (..)`; `KEY` may touch the paren.
            words
                .next()
                .map(|w| w == "key" || w.starts_with("key("))
                .unwrap_or(false)
        }
        "unique" | "check" => paren_follows,
        _ => false,
    }
}

fn split_columns(definition: &str) -> Vec<String> {
    let mut columns = Vec::new();
    let mut token = String::new();
    let mut depth = 0i32;
    for ch in definition.chars() {
        match ch {
            '(' => {
                depth += 1;
                token.push(ch);
            }
            ')' => {
                if depth > 0 {
                    depth -= 1;
                }
                token.push(ch);
            }
            ',' if depth == 0 => {
                if !token.trim().is_empty() {
                    columns.push(token.clone());
                }
                token.clear();
            }
            _ => token.push(ch),
        }
    }
    if !token.trim().is_empty() {
        columns.push(token);
    }
    columns
}

/// Infers the most likely column count from a set of records (uses the maximum
/// observed) and a confidence ratio. Ported from `InferColumnCount`.
pub fn infer_column_count(records: &[Vec<Value>]) -> (usize, f64) {
    if records.is_empty() {
        return (0, 0.0);
    }
    let mut max_columns = 0;
    let mut freq = std::collections::HashMap::new();
    for r in records {
        let c = r.len();
        *freq.entry(c).or_insert(0) += 1;
        if c > max_columns {
            max_columns = c;
        }
    }
    let matching = *freq.get(&max_columns).unwrap_or(&0);
    (max_columns, matching as f64 / records.len() as f64)
}

/// Generates placeholder column names `c0, c1, ...` for a count.
pub fn placeholder_columns(count: usize) -> Vec<String> {
    (0..count).map(|i| format!("c{}", i)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_columns() {
        let cols = parse_create_table_sql(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)",
        );
        assert_eq!(cols, vec!["id", "name", "email"]);
    }

    #[test]
    fn skips_table_constraints() {
        let cols = parse_create_table_sql(
            "CREATE TABLE t (a INT, b INT, PRIMARY KEY(a,b), FOREIGN KEY(b) REFERENCES x(y))",
        );
        assert_eq!(cols, vec!["a", "b"]);
    }

    #[test]
    fn infers_column_count() {
        let records = vec![
            vec![Value::Int(1), Value::Text("a".into())],
            vec![Value::Int(2), Value::Text("b".into())],
        ];
        let (count, conf) = infer_column_count(&records);
        assert_eq!(count, 2);
        assert!((conf - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn placeholders() {
        assert_eq!(placeholder_columns(3), vec!["c0", "c1", "c2"]);
    }
}

#[cfg(test)]
mod constraint_keyword_tests {
    use super::parse_create_table_sql;

    /// The Google Drive `snapshot.db` DDL from the NIST CFReDS Data Leakage
    /// image. `checksum` begins with the letters `check`; it is a column, not a
    /// `CHECK` constraint, and dropping it shifted every later column of every
    /// recovered deleted row by one (`shared` held the checksum, `resource_type`
    /// held `shared`).
    #[test]
    fn a_column_whose_name_begins_with_a_constraint_keyword_is_a_column() {
        let sql = "CREATE TABLE cloud_entry (doc_id TEXT, filename TEXT, modified INTEGER, \
                   created INTEGER, acl_role INTEGER, doc_type INTEGER, removed INTEGER, \
                   size INTEGER, checksum TEXT, shared INTEGER, resource_type TEXT, \
                   PRIMARY KEY (doc_id))";
        let cols = parse_create_table_sql(sql);
        assert_eq!(
            cols,
            [
                "doc_id",
                "filename",
                "modified",
                "created",
                "acl_role",
                "doc_type",
                "removed",
                "size",
                "checksum",
                "shared",
                "resource_type"
            ]
        );
    }

    #[test]
    fn real_table_constraints_are_still_skipped() {
        let sql = "CREATE TABLE t (a INTEGER, unique_id TEXT, primary_owner TEXT, \
                   foreign_ref TEXT, constraint_name TEXT, \
                   CONSTRAINT pk PRIMARY KEY (a), UNIQUE (unique_id), \
                   CHECK (a > 0), FOREIGN KEY (a) REFERENCES u(b), PRIMARY KEY(a), UNIQUE(a), CHECK(a))";
        assert_eq!(
            parse_create_table_sql(sql),
            [
                "a",
                "unique_id",
                "primary_owner",
                "foreign_ref",
                "constraint_name"
            ]
        );
    }
}
