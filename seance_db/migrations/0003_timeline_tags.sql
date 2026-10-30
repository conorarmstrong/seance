-- Add timeline tags for bookmarking important events
CREATE TABLE IF NOT EXISTS timeline_tags (
    id BLOB PRIMARY KEY, -- UUID as BLOB
    case_id BLOB NOT NULL,
    event_id BLOB NOT NULL, -- artifact_id from timeline_events
    examiner TEXT,
    note TEXT,
    created_at INTEGER NOT NULL, -- Unix timestamp
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    UNIQUE(case_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_timeline_tags_case ON timeline_tags(case_id);
CREATE INDEX IF NOT EXISTS idx_timeline_tags_event ON timeline_tags(event_id);
