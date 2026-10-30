-- The evidence-tree listing scanned the whole case to list one node's children.
--
-- get_child_artifacts and get_child_artifacts_filtered filter on
-- (case_id, parent_id) and page with `ORDER BY created_at ASC, id ASC`. The
-- indexes carrying parent_id (0016, 0007, 0018) carry no ordering, so — as with
-- the record lists 0025 fixed — SQLite preferred idx_artifacts_case_created for
-- the ORDER BY and walked every artifact in the case, testing parent_id row by
-- row, then sorted the survivors in a temp b-tree. Measured before this index
-- (release, 2026-09-19): a four-row page under a 220,000-artifact case, 42 ms;
-- the cost grows with the case, not the page. The correlated child_count
-- subquery ROADMAP §5.10 suspected was 1-3 ms of that.
--
-- With created_at and id in the same index the filter and the ordering come
-- from one seek: a page is LIMIT rows from the parent's run, no sort. The
-- (case_id, parent_id) prefix serves every lookup 0016's index served.
CREATE INDEX IF NOT EXISTS idx_artifacts_children_created
    ON artifacts(case_id, parent_id, created_at, id);
