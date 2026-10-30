-- A record a later run answered must leave the counts, and the counts must stay
-- fast (HUNT-107).
--
-- Excluding superseded records by reading `metadata_json` for every row put a
-- full JSON scan under the Analysis index: the record-type census on a
-- 1.75M-artifact case went from a fraction of a second to 96. The exclusion has
-- to come from an index, and the population it describes is tiny — a case that
-- has never had a module re-run holds none at all — so it is a PARTIAL index
-- over exactly the superseded rows. The census then counts the type's whole
-- population from `idx_artifacts_record_type` as before and subtracts what this
-- index holds, which on a real case is a six-millisecond lookup.
--
-- The indexed expression is the same discriminator `idx_artifacts_record_type`
-- carries, so the two describe one population; the `WHERE` is written exactly as
-- the queries write it, because SQLite matches a partial index by that text.

CREATE INDEX IF NOT EXISTS idx_artifacts_superseded
    ON artifacts(
        case_id,
        COALESCE(
            json_extract(metadata_json, '$.type'),
            json_extract(metadata_json, '$.subtype'),
            CASE WHEN json_extract(metadata_json, '$.redo_operation') IS NOT NULL
                  AND json_extract(metadata_json, '$.lsn') IS NOT NULL
                 THEN 'NtfsLogFileRecord' END,
            json_extract(metadata_json, '$.record_type'),
            json_extract(metadata_json, '$.analysis_type'),
            'Unknown'
        )
    )
    WHERE artifact_type = 'ParsedRecord'
      AND json_extract(metadata_json, '$.superseded') = 1;
