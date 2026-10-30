-- Add index to speed up artifact lookups by parent within a case.
-- Note: Unique constraint on (case_id, parent_id, name) is not practical because
-- 'name' is stored inside metadata_json, not as a separate column.
-- Instead, add a composite index for the common parent+type query pattern.
CREATE INDEX IF NOT EXISTS idx_artifacts_case_parent
ON artifacts(case_id, parent_id);
