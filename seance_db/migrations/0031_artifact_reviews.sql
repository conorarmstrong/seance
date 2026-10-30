-- The review ledger, moved off the browser.
--
-- "Which artifacts has anyone opened, and which has anyone cleared?" used to be
-- answered from browser-local storage. That answer is correct for exactly one
-- person on exactly one machine, and the case it is asked about outlives both:
-- when examiner B inherits examiner A's case, B opens the ledger and is told
-- that nothing in the case has ever been looked at. The old screens disclosed
-- the limitation honestly, but a disclosure does not make the handover work.
--
-- OPENED and REVIEWED are two separate assertions and are stored as two
-- separate columns. Opening a row is not clearing it: if the two were one flag,
-- or one nullable timestamp, a scroll past a row would become evidence that the
-- row was examined. They are never summed, and every reviewed row is also an
-- opened row, so the two counts overlap by construction.
CREATE TABLE IF NOT EXISTS artifact_reviews (
    case_id BLOB NOT NULL,
    artifact_id BLOB NOT NULL,
    -- Who looked. Per examiner rather than per browser: that is the whole point
    -- of moving the ledger server-side.
    examiner TEXT NOT NULL,
    -- When this examiner FIRST opened the artifact. Never rewritten by a later
    -- opening, for the same reason `artifact_bookmarks` keeps its `created_at`
    -- on conflict: "when did A first look at this?" is a chain-of-custody
    -- question, and an upsert that overwrites it destroys the only record of the
    -- answer.
    opened_at INTEGER NOT NULL,
    -- When this examiner marked the artifact reviewed, or NULL for opened but
    -- not cleared. NULL here means "no review recorded", never "reviewed at
    -- epoch 0".
    reviewed_at INTEGER,
    -- The composite primary key IS the UNIQUE (case_id, artifact_id, examiner)
    -- constraint the ledger needs, and it gives the per-case and per-artifact
    -- lookups their index without a second one. Two examiners hold two
    -- independent rows for the same artifact, which is what makes "what has
    -- nobody opened?" answerable.
    PRIMARY KEY (case_id, artifact_id, examiner),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
);

-- Per-examiner roll-ups (the stats panel) read case_id + examiner; the primary
-- key is ordered case_id, artifact_id, examiner and cannot serve them.
CREATE INDEX IF NOT EXISTS idx_artifact_reviews_case_examiner
    ON artifact_reviews(case_id, examiner);

-- The reviewed-id listing filters on `reviewed_at IS NOT NULL` within a case.
-- A partial index keeps it proportional to the reviewed set rather than to the
-- opened set, which on a large case is orders of magnitude bigger.
CREATE INDEX IF NOT EXISTS idx_artifact_reviews_case_reviewed
    ON artifact_reviews(case_id, artifact_id) WHERE reviewed_at IS NOT NULL;

-- ON DELETE CASCADE from `artifacts` needs the child side indexed, or deleting
-- one artifact scans the whole ledger.
CREATE INDEX IF NOT EXISTS idx_artifact_reviews_artifact
    ON artifact_reviews(artifact_id);

-- The append-only half of the ledger.
--
-- `artifact_reviews` holds the CURRENT state, and a current-state table cannot
-- answer "what did the previous examiner do, and did they change their mind?".
-- Withdrawing a review clears `reviewed_at` in the state table; if that were the
-- only record, a review that was made and then retracted would be
-- indistinguishable from one that was never made. In a chain-of-custody-adjacent
-- ledger that difference is exactly the thing a handover, or a cross-examination,
-- turns on. So a withdrawal APPENDS a row here rather than erasing anything.
--
-- What is recorded is state TRANSITIONS, not activity: the first opening of an
-- artifact by an examiner, a review being set, and a review being withdrawn. A
-- repeat opening changes nothing and writes nothing, so this table is bounded by
-- the size of `artifact_reviews` plus the number of review changes, not by how
-- far anybody scrolled.
--
-- This is deliberately NOT the main `audit_log`. That log is hash-chained and is
-- read start-to-finish by an examiner; per-artifact openings would arrive in
-- bursts of hundreds as someone scrolls a grid and would bury every deliberate
-- act in it. The API records one summarising `audit_log` entry per batch, and
-- the per-artifact detail lives here.
CREATE TABLE IF NOT EXISTS artifact_review_events (
    id BLOB PRIMARY KEY,
    case_id BLOB NOT NULL,
    artifact_id BLOB NOT NULL,
    examiner TEXT NOT NULL,
    -- 'opened' | 'reviewed' | 'review_withdrawn'. A closed vocabulary; the
    -- writer is the only thing that inserts here.
    action TEXT NOT NULL,
    at INTEGER NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_artifact_review_events_case_at
    ON artifact_review_events(case_id, at);
CREATE INDEX IF NOT EXISTS idx_artifact_review_events_artifact
    ON artifact_review_events(artifact_id);
