-- Expression / partial indices for the two hot json_extract discriminators.
-- Both queries previously scanned every artifact in the case and parsed the
-- metadata_json blob per row; record-type counting also built a temp-b-tree to
-- group the extracted key. Precomputing the discriminator in the index B-tree
-- makes the read covering (no per-row JSON parse) and the grouping index-ordered.

-- record_type_counts: WHERE case_id = ? AND artifact_type = 'ParsedRecord'
-- GROUP BY COALESCE(type, subtype, record_type, analysis_type, 'Unknown').
-- The stored second column IS that COALESCE, so for a single case the rows come
-- out already grouped -- no temp-b-tree for GROUP BY, and no JSON parse per row.
-- Partial on ParsedRecord so it only indexes the rows the query counts.
CREATE INDEX IF NOT EXISTS idx_artifacts_record_type
    ON artifacts(
        case_id,
        COALESCE(
            json_extract(metadata_json, '$.type'),
            json_extract(metadata_json, '$.subtype'),
            json_extract(metadata_json, '$.record_type'),
            json_extract(metadata_json, '$.analysis_type'),
            'Unknown'
        )
    )
    WHERE artifact_type = 'ParsedRecord';

-- get_geo_map_points: WHERE case_id = ? AND gps_lat IS NOT NULL AND gps_lon
-- IS NOT NULL. A partial index over only the GPS-bearing rows lets the planner
-- seek straight to them by case_id instead of scanning every case artifact
-- (most of which carry no coordinates).
CREATE INDEX IF NOT EXISTS idx_artifacts_geo
    ON artifacts(case_id)
    WHERE json_extract(metadata_json, '$.gps_lat') IS NOT NULL
      AND json_extract(metadata_json, '$.gps_lon') IS NOT NULL;
