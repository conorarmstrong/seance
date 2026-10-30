-- Add indexes to timeline_events for better query performance
-- These indexes are critical for:
-- 1. Deleting events by case_id (case deletion)
-- 2. Querying events by case_id (timeline view)
-- 3. Deleting events by artifact_id (artifact deletion)

CREATE INDEX IF NOT EXISTS idx_timeline_events_case_id ON timeline_events(case_id);
CREATE INDEX IF NOT EXISTS idx_timeline_events_artifact_id ON timeline_events(artifact_id);
CREATE INDEX IF NOT EXISTS idx_timeline_events_timestamp ON timeline_events(timestamp);

-- Also add index on artifacts.case_id for better join and delete performance
CREATE INDEX IF NOT EXISTS idx_artifacts_case_id ON artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_parent_id ON artifacts(parent_id);
