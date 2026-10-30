-- Examiner assignment (ROADMAP §3.15).
--
-- An owner allocates a named set of artifacts to a named examiner. The ledger
-- in 0031 records who opened and who reviewed what; it records nothing about
-- who was ASKED to. This table is that missing half.
--
-- Progress is never stored here. It is derived, at read time, from
-- `artifact_reviews` rows whose `examiner` is the assignee's username. A stored
-- progress counter would be a second source of truth that could disagree with
-- the ledger, and a colleague's review of an assigned item is not the
-- assignee's work: it does not count toward the assignee's progress.
--
-- A withdrawal is RECORDED (`withdrawn_at`, `withdrawn_by`), never a DELETE.
-- "Was this examiner ever told to look at these items?" is a question a
-- handover or a cross-examination can turn on, and a deleted assignment would
-- answer it "no".
CREATE TABLE IF NOT EXISTS case_assignments (
    id BLOB PRIMARY KEY,
    case_id BLOB NOT NULL,
    -- The examiner the work is allocated to. Cascades like `case_access`
    -- (0020): deleting the user removes the grants and the assignments with
    -- them, so no assignment names an account that no longer exists.
    assignee_user_id BLOB NOT NULL,
    -- The acting user's id. Plain BLOB (no FK), as `case_access.granted_by`:
    -- the record of who assigned survives that user's deletion.
    assigned_by BLOB,
    note TEXT,
    created_at INTEGER NOT NULL,
    -- NULL = active. Set once; a withdrawn assignment is never reactivated.
    withdrawn_at INTEGER,
    withdrawn_by BLOB,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (assignee_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_case_assignments_case ON case_assignments(case_id);
CREATE INDEX IF NOT EXISTS idx_case_assignments_assignee ON case_assignments(assignee_user_id);

-- The artifacts an assignment covers. An explicit id set, not a saved filter:
-- a filter re-evaluated later can name different rows than the ones the
-- examiner was given, and "what was assigned?" must have one answer.
CREATE TABLE IF NOT EXISTS case_assignment_items (
    assignment_id BLOB NOT NULL,
    artifact_id BLOB NOT NULL,
    PRIMARY KEY (assignment_id, artifact_id),
    FOREIGN KEY (assignment_id) REFERENCES case_assignments(id) ON DELETE CASCADE,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
);

-- ON DELETE CASCADE from `artifacts` needs the child side indexed.
CREATE INDEX IF NOT EXISTS idx_case_assignment_items_artifact
    ON case_assignment_items(artifact_id);
