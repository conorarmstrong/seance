-- Personal bookmarks (ROADMAP §3.15; owner decision 2026-09-26, option 1).
--
-- A personal bookmark is a private scratch mark. Only its owner sees it, and it
-- NEVER reaches a report: the report's Findings / Bookmarks section is built
-- from `artifact_bookmarks` (0009) alone, which is the case's shared set.
-- Turning a personal mark into a shared bookmark is an explicit, audited step
-- (promotion); nothing moves between the two tables implicitly.
--
-- This is a separate table rather than a visibility column on
-- `artifact_bookmarks` so that no reader of the shared table — the report, the
-- CSV export, the bookmark grid — can pick up a private mark by forgetting a
-- WHERE clause. The report does state, as a count, how many personal marks
-- exist and were excluded, so the exclusion is on the record and not silent.
CREATE TABLE IF NOT EXISTS personal_bookmarks (
    id BLOB PRIMARY KEY,
    case_id BLOB NOT NULL,
    artifact_id BLOB NOT NULL,
    -- The owner. Cascades with the user: a scratch mark is its author's own and
    -- has no reader once the author is gone. A promoted mark already lives on
    -- in `artifact_bookmarks` and in the audit log.
    owner_user_id BLOB NOT NULL,
    note TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    -- Set when the mark was promoted to the shared set; the shared bookmark's
    -- id is kept so the two records can be tied together.
    promoted_at INTEGER,
    promoted_bookmark_id BLOB,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE,
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (case_id, artifact_id, owner_user_id)
);

CREATE INDEX IF NOT EXISTS idx_personal_bookmarks_owner
    ON personal_bookmarks(case_id, owner_user_id);
CREATE INDEX IF NOT EXISTS idx_personal_bookmarks_artifact
    ON personal_bookmarks(artifact_id);
CREATE INDEX IF NOT EXISTS idx_personal_bookmarks_user
    ON personal_bookmarks(owner_user_id);
