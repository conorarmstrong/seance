CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id BLOB,
    timestamp TEXT NOT NULL,
    user_id TEXT NOT NULL DEFAULT 'system',
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id BLOB,
    details TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_case ON audit_log(case_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
