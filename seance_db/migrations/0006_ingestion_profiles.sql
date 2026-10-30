-- Add ingestion profiles for controlling which modules run during analysis
CREATE TABLE IF NOT EXISTS ingestion_profiles (
    id BLOB PRIMARY KEY NOT NULL,
    case_id BLOB NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled_modules TEXT NOT NULL,    -- JSON array of module IDs
    disabled_modules TEXT NOT NULL,   -- JSON array of module IDs
    is_active INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
);

-- Index for finding active profile per case
CREATE INDEX IF NOT EXISTS idx_profiles_case_active
ON ingestion_profiles(case_id, is_active);

-- Add ad-hoc execution job tracking
CREATE TABLE IF NOT EXISTS ad_hoc_jobs (
    id BLOB PRIMARY KEY NOT NULL,
    case_id BLOB NOT NULL,
    module_id TEXT NOT NULL,
    target_artifact_id BLOB NOT NULL,
    status TEXT NOT NULL,             -- 'pending', 'running', 'complete', 'failed'
    artifacts_produced INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    created_at INTEGER NOT NULL,
    completed_at INTEGER,
    FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY(target_artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
);

-- Index for finding jobs by case and status
CREATE INDEX IF NOT EXISTS idx_jobs_case_status
ON ad_hoc_jobs(case_id, status);

-- Index for finding jobs by status (for polling pending/running jobs)
CREATE INDEX IF NOT EXISTS idx_jobs_status
ON ad_hoc_jobs(status);
