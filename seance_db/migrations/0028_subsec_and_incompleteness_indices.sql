-- Two indices the last wave's queries need.
--
-- Foreign keys are enabled per-connection (PRAGMA foreign_keys on each pooled
-- connection), not by these files; nothing here depends on that, but a reader
-- comparing this migration with the FK actions declared in 0001 should know
-- where enforcement is turned on.

-- 1. Timeline pagination now breaks same-second ties on sub-second precision.
--
-- 0023 added idx_timeline_events_case_ts on (case_id, timestamp DESC, id ASC).
-- That matched the query of the day exactly. It no longer does: every timeline
-- read orders by
--     timestamp DESC, timestamp_subsec_nanos DESC, id ASC
-- because sorting same-second events by artifact id put an EVTX sequence into
-- arbitrary order, and within one second that nanosecond ordering IS the
-- sequence an intrusion is reconstructed from.
--
-- With the 0023 index SQLite can still seek by case_id and read in timestamp
-- order, but it cannot satisfy the second key, so it materialises the case's
-- rows and builds a TEMP B-TREE for every page and every export. On a case with
-- millions of events that is the whole timeline sorted per request.
--
-- Column directions match the ORDER BY term for term, so the planner walks the
-- index and a page becomes a seek plus LIMIT rows with no sort. The 0023 index
-- is left in place: it is a strict prefix of this one and still serves the
-- ascending-export and range-scan variants.
CREATE INDEX IF NOT EXISTS idx_timeline_events_case_ts_subsec
    ON timeline_events(case_id, timestamp DESC, timestamp_subsec_nanos DESC, id ASC);

-- 2. The completeness census (`get_case_incompleteness`).
--
-- The census runs six queries per case, each of the form
--     WHERE case_id = ? AND json_extract(metadata_json, '$.<axis>_incomplete') = 1
-- and two of them additionally GROUP BY
--     json_extract(metadata_json, '$.<axis>_incomplete_reason').
-- Incomplete artifacts are a small minority of a case, but without an index
-- every one of those queries reads and JSON-parses every artifact row in the
-- case to find them, and the two grouped ones then build a temp b-tree.
--
-- Partial on the flag so the index holds ONLY the incomplete rows (a few
-- thousand at worst, against millions of artifacts), and carrying the reason as
-- the second column makes the GROUP BY index-ordered and the read covering --
-- no per-row JSON parse at all.
--
-- The partial WHERE clause is character-for-character the query's own predicate;
-- SQLite will not use a partial index whose WHERE it cannot match against the
-- query's terms.
CREATE INDEX IF NOT EXISTS idx_artifacts_content_incomplete
    ON artifacts(case_id, json_extract(metadata_json, '$.content_incomplete_reason'))
    WHERE json_extract(metadata_json, '$.content_incomplete') = 1;

CREATE INDEX IF NOT EXISTS idx_artifacts_inventory_incomplete
    ON artifacts(case_id, json_extract(metadata_json, '$.inventory_incomplete_reason'))
    WHERE json_extract(metadata_json, '$.inventory_incomplete') = 1;
