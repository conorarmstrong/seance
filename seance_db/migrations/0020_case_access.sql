-- Per-case access control (multi-user v1.0).
--
-- One row per (case, user) granting an access level. Admins bypass this table
-- entirely in the API layer; an examiner may see and act on a case only when a
-- row here grants them access. The case creator is granted 'owner' at creation
-- time so they retain control of the case they opened.
--
-- access_level:
--   read_only   - may view the case and its artifacts
--   read_write  - may view and mutate (tag, bookmark, ingest, etc.)
--   owner       - read_write plus the right to grant/revoke access
--
-- FKs cascade both ways: deleting a case or a user removes their grants, so no
-- dangling access rows survive. Requires PRAGMA foreign_keys = ON (set per
-- connection in SqliteConnection::new).
CREATE TABLE IF NOT EXISTS case_access (
    case_id BLOB NOT NULL,       -- UUID as BLOB (references cases.id)
    user_id BLOB NOT NULL,       -- UUID as BLOB (references users.id)
    access_level TEXT NOT NULL DEFAULT 'read_write'
        CHECK(access_level IN ('read_only', 'read_write', 'owner')),
    granted_by BLOB,             -- UUID of the granting user (NULL if system)
    granted_at INTEGER NOT NULL, -- Unix timestamp (seconds)
    PRIMARY KEY (case_id, user_id),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Lookup by user drives the case-list filter (list_accessible_case_ids).
CREATE INDEX IF NOT EXISTS idx_case_access_user ON case_access(user_id);
