CREATE TABLE IF NOT EXISTS virtual_columns (
    id TEXT PRIMARY KEY, -- We'll keep ID as TEXT for virtual columns since they have string IDs like "vc_resource_path"
    case_id BLOB NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    column_type TEXT NOT NULL,
    sources_json TEXT NOT NULL,
    default_visible INTEGER NOT NULL DEFAULT 0,
    built_in INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_virtual_columns_case_id ON virtual_columns(case_id);