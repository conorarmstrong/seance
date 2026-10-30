-- Add unique constraint on ingestion profile names per case
CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_case_name
ON ingestion_profiles(case_id, name);

-- Add composite index for common artifact query pattern: case_id + artifact_type
CREATE INDEX IF NOT EXISTS idx_artifacts_case_type
ON artifacts(case_id, artifact_type);
