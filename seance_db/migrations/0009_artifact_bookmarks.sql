-- Artifact Bookmarking System
-- Allows bookmarking any artifact type with notes and categories

-- Bookmark categories/labels for organizing findings
CREATE TABLE IF NOT EXISTS bookmark_categories (
    id BLOB PRIMARY KEY,
    case_id BLOB NOT NULL,
    name TEXT NOT NULL,
    color TEXT DEFAULT '#ffc107',  -- Yellow default (matches tag color)
    created_at INTEGER NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    UNIQUE(case_id, name)
);

CREATE INDEX IF NOT EXISTS idx_bookmark_categories_case ON bookmark_categories(case_id);

-- Generic artifact bookmarks (works for any artifact type)
CREATE TABLE IF NOT EXISTS artifact_bookmarks (
    id BLOB PRIMARY KEY,
    case_id BLOB NOT NULL,
    artifact_id BLOB NOT NULL,
    category_id BLOB,              -- Optional category reference
    note TEXT,                     -- Investigator notes
    examiner TEXT,                 -- Who created this bookmark
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES bookmark_categories(id) ON DELETE SET NULL,
    UNIQUE(case_id, artifact_id)   -- One bookmark per artifact per case
);

CREATE INDEX IF NOT EXISTS idx_artifact_bookmarks_case ON artifact_bookmarks(case_id);
CREATE INDEX IF NOT EXISTS idx_artifact_bookmarks_artifact ON artifact_bookmarks(artifact_id);
CREATE INDEX IF NOT EXISTS idx_artifact_bookmarks_category ON artifact_bookmarks(category_id);
