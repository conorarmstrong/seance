-- Saved filters for compound filtering system
CREATE TABLE IF NOT EXISTS filters (
    id BLOB PRIMARY KEY,
    case_id BLOB,                           -- NULL for global/predefined filters
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    filter_json TEXT NOT NULL,              -- JSON FilterCondition
    is_predefined INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_filters_case_id ON filters(case_id);
CREATE INDEX IF NOT EXISTS idx_filters_predefined ON filters(is_predefined);
