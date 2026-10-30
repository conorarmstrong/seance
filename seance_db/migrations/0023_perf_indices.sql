-- Performance indices for the hot read paths (timeline pagination, per-source
-- timeline, recent-artifacts). Before these, filtering by case_id then
-- ORDER BY timestamp/created_at forced a full scan of the case's rows plus a
-- temp-b-tree sort on every page load and histogram. The composite indices let
-- the planner satisfy WHERE + ORDER BY directly by index order.

-- Timeline pagination: WHERE case_id = ? ORDER BY timestamp DESC, id ASC.
-- Column sort directions match the query exactly so no separate sort is needed.
CREATE INDEX IF NOT EXISTS idx_timeline_events_case_ts
    ON timeline_events(case_id, timestamp DESC, id ASC);

-- Per-source timeline: WHERE case_id = ? AND source_module = ? ORDER BY timestamp.
CREATE INDEX IF NOT EXISTS idx_timeline_events_case_src_ts
    ON timeline_events(case_id, source_module, timestamp DESC);

-- Recent artifacts / record lists: WHERE case_id = ? ORDER BY created_at DESC.
CREATE INDEX IF NOT EXISTS idx_artifacts_case_created
    ON artifacts(case_id, created_at DESC);
