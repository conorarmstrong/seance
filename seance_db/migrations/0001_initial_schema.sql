-- Add migration script here
CREATE TABLE IF NOT EXISTS cases (
    id BLOB PRIMARY KEY, -- UUID as BLOB
    name TEXT NOT NULL,
    created_at TEXT NOT NULL, -- ISO 8601 string
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id BLOB PRIMARY KEY, -- UUID as BLOB
    case_id BLOB NOT NULL,
    parent_id BLOB, -- Optional UUID as BLOB
    artifact_type TEXT NOT NULL,
    metadata_json TEXT NOT NULL, -- JSON string
    created_at TEXT NOT NULL, -- ISO 8601 string when recorded
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id BLOB PRIMARY KEY, -- UUID as BLOB
    case_id BLOB NOT NULL,
    artifact_id BLOB NOT NULL,
    timestamp INTEGER NOT NULL, -- Unix timestamp
    timestamp_desc TEXT NOT NULL,
    source_module TEXT NOT NULL,
    short_desc TEXT NOT NULL,
    full_details TEXT NOT NULL, -- Full JSON or text details
    FOREIGN KEY (case_id) REFERENCES cases(id),
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
);
