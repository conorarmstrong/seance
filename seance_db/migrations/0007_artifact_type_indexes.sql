-- Add missing indexes for artifact queries
-- Addresses Performance Issue from Code Review (2025-12-07)
--
-- These indexes improve performance for:
-- 1. Filtering artifacts by type (sources_only, statistics queries)
-- 2. Tree navigation queries (case_id + parent_id + artifact_type)
-- 3. Type-specific artifact searches

-- Single-column index for artifact_type filtering
-- Used in: sources_only filter, artifact statistics (GROUP BY artifact_type)
CREATE INDEX IF NOT EXISTS idx_artifacts_artifact_type ON artifacts(artifact_type);

-- Composite index for tree navigation queries
-- Covers the common query pattern: WHERE case_id = ? AND parent_id = ? AND artifact_type IN (...)
-- This is a covering index for get_child_artifacts_filtered()
CREATE INDEX IF NOT EXISTS idx_artifacts_tree_navigation ON artifacts(case_id, parent_id, artifact_type);

-- Note: SQLite can use either idx_artifacts_case_id OR idx_artifacts_tree_navigation
-- for queries filtering only by case_id. The tree_navigation index covers both use cases.
