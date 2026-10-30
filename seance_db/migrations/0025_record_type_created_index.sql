-- Record listings order by created_at, which defeated 0024's expression index.
--
-- 0024 added idx_artifacts_record_type on (case_id, <discriminator expr>) for
-- ParsedRecord. That serves a bare count, but every record list also does
-- `ORDER BY created_at ASC, id ASC`. Faced with a filter index that carries no
-- ordering, SQLite instead picks idx_artifacts_case_created (case_id only),
-- scans every artifact in the case, and builds a temp b-tree for the sort — on
-- a 500k-artifact case that is ~0.5s per query, twice per request.
--
-- Carrying created_at (and id, the tiebreaker) in the same index makes the
-- filter and the ordering come from one index scan, so a page is a seek plus
-- LIMIT rows with no sort. The discriminator expression must stay character-
-- for-character identical to the one the queries use, including the 'Unknown'
-- fallback, or SQLite will not match it.
CREATE INDEX IF NOT EXISTS idx_artifacts_record_type_created
    ON artifacts(
        case_id,
        COALESCE(
            json_extract(metadata_json, '$.type'),
            json_extract(metadata_json, '$.subtype'),
            json_extract(metadata_json, '$.record_type'),
            json_extract(metadata_json, '$.analysis_type'),
            'Unknown'
        ),
        created_at,
        id
    )
    WHERE artifact_type = 'ParsedRecord';
