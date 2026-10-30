-- One row per ingest run, so a case can say whether each exhibit's processing
-- finished (HUNT-113).
--
-- An ingest the kernel killed part-way through a directory walk left a case
-- that looked complete: the sources were listed exactly as the ones that had
-- finished, and the completeness census counted only what the parsers
-- themselves reported. Nothing recorded that a walk had started, so nothing on
-- the next start could see that it never ended. `ad_hoc_jobs` carries module
-- re-runs only.
--
-- A row is written when a root exhibit is queued for processing and completed
-- when the orchestrator reaches idle for its case (or the examiner cancels).
-- On start, every row still `running` was left by a process that stopped: it
-- is marked `interrupted`, and its source artifact is stamped incomplete so the
-- census, the report and every screen that offers the source say so.
--
-- `artifacts_recorded` is the source's subtree count at the moment the row was
-- closed — for an interrupted run, what was recorded before it stopped.

CREATE TABLE IF NOT EXISTS ingest_runs (
    id BLOB PRIMARY KEY,
    case_id BLOB NOT NULL,
    source_artifact_id BLOB NOT NULL,
    source_label TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    -- 'running' | 'completed' | 'cancelled' | 'interrupted'
    status TEXT NOT NULL,
    artifacts_recorded INTEGER,
    detail TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ingest_runs_case_status ON ingest_runs(case_id, status);
CREATE INDEX IF NOT EXISTS idx_ingest_runs_source ON ingest_runs(source_artifact_id);
