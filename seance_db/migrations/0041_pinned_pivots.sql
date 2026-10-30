-- A pivot result pinned to the case, so the answer to "everything that touches
-- this address" reaches the report instead of being re-derived by hand
-- (ROADMAP §5.13).
--
-- The pivot is the move an examiner makes constantly, and its answer was
-- previously a transient panel: nothing carried "these eleven artifacts are
-- what referenced that account" into the document, so the examiner either
-- re-ran the search while writing or transcribed the counts into prose, where
-- nothing could check them.
--
-- # Why the snapshot is stored rather than recomputed
--
-- A pinned pivot records BOTH what the examiner saw when they pinned it and
-- what the same value answers at report time. Storing only the value would
-- mean the report quietly said something different after the next ingest, with
-- nothing to show that it had changed. Storing only the snapshot would mean the
-- report described a case that has since grown. So both are carried, and a
-- difference between them is itself on the record: it says the case answered
-- this question differently on two dates.
--
-- `groups_json` is the grouped result verbatim as the pivot endpoint returned
-- it — kind, count and the samples — so the report renders what the examiner
-- saw and not a re-rendering of it. `truncated` travels with it because a
-- capped pivot's per-kind counts are a sample, and a sample presented as a
-- total on a court-facing surface is the defect class this project treats as
-- HIGH.
--
-- One row per (case, value): pinning the same value twice is the same
-- assertion, and the second pin refreshes the snapshot rather than filing a
-- duplicate.

CREATE TABLE IF NOT EXISTS pinned_pivots (
    id BLOB PRIMARY KEY,
    case_id BLOB NOT NULL,
    value TEXT NOT NULL,
    -- Why the examiner pinned it. Optional, and absent rather than empty.
    note TEXT,
    examiner TEXT NOT NULL,
    pinned_at INTEGER NOT NULL,
    -- The snapshot, as the pivot answered at `pinned_at`.
    total_matches INTEGER NOT NULL,
    grouped INTEGER NOT NULL,
    truncated INTEGER NOT NULL,
    groups_json TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pinned_pivots_case_value
    ON pinned_pivots(case_id, value);
CREATE INDEX IF NOT EXISTS idx_pinned_pivots_case_time
    ON pinned_pivots(case_id, pinned_at DESC);
