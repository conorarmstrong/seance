-- Processing log: records every module execution for visibility
CREATE TABLE IF NOT EXISTS processing_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id BLOB NOT NULL,
    artifact_id BLOB NOT NULL,
    module_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'complete',
    artifacts_produced INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_processing_log_artifact ON processing_log(artifact_id);
CREATE INDEX IF NOT EXISTS idx_processing_log_case ON processing_log(case_id);
