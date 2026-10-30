CREATE TABLE IF NOT EXISTS integrity_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id BLOB NOT NULL,
    artifact_id BLOB NOT NULL,
    timestamp TEXT NOT NULL,
    computed_md5 TEXT,
    computed_sha1 TEXT,
    computed_sha256 TEXT,
    expected_md5 TEXT,
    expected_sha1 TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',
    details TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_integrity_checks_artifact ON integrity_checks(artifact_id);
CREATE INDEX IF NOT EXISTS idx_integrity_checks_case ON integrity_checks(case_id);
