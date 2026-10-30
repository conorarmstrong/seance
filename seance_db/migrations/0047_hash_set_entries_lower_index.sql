-- Case-insensitive hash-set matching on an expression index.
--
-- Every hash-set match compares LOWER(hash_set_entries.hash_value) with the
-- LOWER() of an artifact's md5/sha1/sha256 (`lookup_hash`, `list_hash_hits`,
-- `count_hash_matches_for_case` and the file grid's known-status column and
-- filter). Hash text is compared case-insensitively because sets and tools
-- disagree about the case of hex. Wrapping the stored column in LOWER() made
-- the plain index on `hash_value` (0010, BINARY collation) unusable, so each
-- match was a scan of the whole entries table -- millions of rows for an
-- NSRL-sized set, once per displayed grid row.
--
-- The queries use the byte-identical expression `LOWER(<alias>.hash_value)`,
-- which is what lets SQLite match this index (including multi-probe for the
-- `IN (LOWER(a.md5_hash), ...)` form). The plan is pinned by
-- `tests/hash_match_plan_test.rs`.
CREATE INDEX IF NOT EXISTS idx_hash_set_entries_lower_hash
    ON hash_set_entries(LOWER(hash_value));
