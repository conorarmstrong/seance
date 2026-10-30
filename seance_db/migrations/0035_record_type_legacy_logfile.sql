-- UI-009: a case ingested before the `$LogFile` type fix listed the largest
-- record class it holds as "1".
--
-- NTFS `$LogFile` records carried no `$.type`, so the record-type discriminator
-- fell through onto `$.record_type` -- a NUMERIC field describing one field of
-- one record -- and 73,640 records appeared under a card and a viewer heading
-- titled `1`. `seance_plugin_logfile` now writes `"type": "NtfsLogFileRecord"`,
-- which fixes every ingest from that change on. It does nothing for artifacts
-- already written.
--
-- The repair for those is made at READ time, in the discriminator itself, and
-- NOT by back-filling `$.type` onto the stored rows. Those rows belong to cases
-- that have been examined and may have been reported on and tendered; this
-- product's position is that what it stored is what it found, and a migration
-- that edits ingested artifact metadata to improve a label is a mutation of the
-- record that nothing afterwards would show. The audit chain covers the audit
-- log, not artifact metadata. So: stored bytes untouched, presentation
-- corrected for every case, old and new.
--
-- What this migration does is the consequence of that decision. Both expression
-- indices carry the discriminator character-for-character, and SQLite will not
-- match an index whose expression differs by so much as a token -- so changing
-- the expression without changing them would silently drop every record listing
-- back to a full case scan plus a temp b-tree sort (0025's measurement: ~0.5s
-- per query on a 500k-artifact case, twice per request). They are dropped and
-- rebuilt on the new expression.
--
-- WHAT THIS COSTS ON AN EXISTING CASE. Rebuilding two partial expression
-- indices means SQLite evaluating the discriminator once per ParsedRecord row
-- and writing two B-trees. On a case with a few hundred thousand records that is
-- seconds; on the 4M-artifact cases this product is built for it is minutes, and
-- it happens once, at the first start after upgrading, while migrations hold the
-- database. An operator upgrading a large workspace should expect the server to
-- take longer than usual to come up exactly once. The alternative -- leaving the
-- old indices in place -- is not "faster", it is a silent full-table scan plus a
-- temp-B-tree sort on every record listing thereafter.
--
-- The new arm sits AFTER `$.type`, so a record that carries its own type is
-- never relabelled by it, and `$.redo_operation` + `$.lsn` together are what
-- make the shape recognisably a `$LogFile` record: `seance_plugin_logfile` is
-- the only emitter of `redo_operation` in the tree, and requiring `lsn` beside
-- it excludes the MFT scanner in `seance_plugin_memory_windows`, which emits an
-- `lsn` of its own and no redo operation.

DROP INDEX IF EXISTS idx_artifacts_record_type;
DROP INDEX IF EXISTS idx_artifacts_record_type_created;

-- 0024's index: the GROUP BY for record_type_counts.
CREATE INDEX IF NOT EXISTS idx_artifacts_record_type
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
    WHERE artifact_type = 'ParsedRecord';

-- 0025's index: the same discriminator plus the listing order, so a page is a
-- seek plus LIMIT rows with no sort.
CREATE INDEX IF NOT EXISTS idx_artifacts_record_type_created
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
        ),
        created_at,
        id
    )
    WHERE artifact_type = 'ParsedRecord';
