-- Generated columns exposing common file-browse fields from artifacts.metadata_json.
-- VIRTUAL (not STORED): SQLite only allows VIRTUAL generated columns via
-- ALTER TABLE ADD COLUMN, and they add no storage overhead.
-- Follows the pattern established by 0005 (timeline_events.filename).
ALTER TABLE artifacts ADD COLUMN name TEXT GENERATED ALWAYS AS (json_extract(metadata_json, '$.name')) VIRTUAL;
ALTER TABLE artifacts ADD COLUMN path TEXT GENERATED ALWAYS AS (json_extract(metadata_json, '$.path')) VIRTUAL;
ALTER TABLE artifacts ADD COLUMN size INTEGER GENERATED ALWAYS AS (json_extract(metadata_json, '$.size')) VIRTUAL;
ALTER TABLE artifacts ADD COLUMN is_directory INTEGER GENERATED ALWAYS AS (json_extract(metadata_json, '$.is_directory')) VIRTUAL;
ALTER TABLE artifacts ADD COLUMN is_deleted INTEGER GENERATED ALWAYS AS (json_extract(metadata_json, '$.deleted')) VIRTUAL;
ALTER TABLE artifacts ADD COLUMN modified TEXT GENERATED ALWAYS AS (json_extract(metadata_json, '$.modified')) VIRTUAL;

-- Folder navigation: WHERE case_id = ? AND parent_id = ? ... ORDER BY name.
CREATE INDEX IF NOT EXISTS idx_artifacts_browse_children ON artifacts(case_id, parent_id, name);

-- Subtree listing: WHERE case_id = ? AND artifact_type = 'FileEntry' ... ORDER BY name.
CREATE INDEX IF NOT EXISTS idx_artifacts_browse_type_name ON artifacts(case_id, artifact_type, name);
