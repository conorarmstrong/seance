//! Examiner assignment and personal bookmarks (ROADMAP §3.15).
//!
//! Two pieces of case-workflow state that sit beside the review ledger
//! (`artifact_reviews`, migration 0031) and the shared bookmark set
//! (`artifact_bookmarks`, migration 0009):
//!
//! * **Assignment** — an owner allocates an explicit set of artifacts to a
//!   named examiner. Progress is DERIVED from the ledger at read time and
//!   counts only the assignee's own openings and reviews; a colleague's review
//!   of an assigned item is not the assignee's work.
//! * **Personal bookmarks** — a private scratch mark visible only to its owner
//!   and never reported. Promoting one into the shared set is an explicit step
//!   the API audits.

use super::*;

/// Most artifacts one assignment may name. A request over it is REFUSED in
/// full, never truncated: a truncated assignment would tell the owner the
/// examiner had been given work that was never recorded.
pub const ASSIGNMENT_ITEMS_MAX: usize = 10_000;

/// Page ceiling for an assignment's queue.
pub const ASSIGNMENT_QUEUE_PAGE_MAX: usize = 1_000;

/// Page ceiling for a user's personal bookmarks.
pub const PERSONAL_BOOKMARK_PAGE_MAX: usize = 1_000;

/// One assignment as stored, with the assignee's username resolved.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CaseAssignment {
    pub id: Uuid,
    pub case_id: Uuid,
    pub assignee_user_id: Uuid,
    /// The username the review ledger is keyed on.
    pub assignee_username: String,
    pub assigned_by: Option<Uuid>,
    pub note: Option<String>,
    pub created_at: i64,
    /// `None` while the assignment is active.
    pub withdrawn_at: Option<i64>,
    pub withdrawn_by: Option<Uuid>,
    /// The owner's target, Unix seconds. Whether it has been missed is derived
    /// from progress at read time, never stored.
    pub due_at: Option<i64>,
    /// The assignment this one replaced, when it came from a reassignment.
    pub reassigned_from: Option<Uuid>,
    /// How many artifacts the assignment names (still present in the case).
    pub item_count: i64,
}

/// An assignment's progress, derived from the review ledger.
///
/// `opened_by_assignee` and `reviewed_by_assignee` overlap by construction —
/// every reviewed row is also an opened row (migration 0031) — and are never
/// added together.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct AssignmentProgress {
    pub total: i64,
    pub opened_by_assignee: i64,
    pub reviewed_by_assignee: i64,
}

/// One item in an assignee's remaining queue.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AssignmentQueueItem {
    pub artifact_id: Uuid,
    pub artifact_type: String,
    /// When the ASSIGNEE first opened it, or `None` for not yet opened.
    pub opened_at: Option<i64>,
}

/// Why an assignment could not be created. Distinguished so the API can
/// return 400 with the reason rather than a bare 500.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignmentRefusal {
    /// No artifacts named.
    Empty,
    /// More than [`ASSIGNMENT_ITEMS_MAX`] artifacts named.
    OverCap(usize),
    /// These ids are not artifacts of this case. Nothing was written.
    NotInCase(Vec<Uuid>),
}

/// Why an assignment could not be reassigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassignRefusal {
    /// No such assignment in this case.
    NotFound,
    /// It was already withdrawn (or already reassigned): there is nothing to
    /// move. Nothing was written.
    AlreadyWithdrawn,
}

/// A personal (private, never-reported) bookmark.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PersonalBookmark {
    pub id: Uuid,
    pub case_id: Uuid,
    pub artifact_id: Uuid,
    pub owner_user_id: Uuid,
    pub note: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Set once the mark has been promoted to the shared set.
    pub promoted_at: Option<i64>,
    pub promoted_bookmark_id: Option<Uuid>,
    /// True only while the shared bookmark this mark was promoted to still
    /// exists, which is exactly when the report carries it. A promoted mark
    /// whose shared bookmark was deleted is excluded again and may be promoted
    /// again, so `promoted_at` alone must not be read as "in the report".
    pub in_shared_set: bool,
    /// The artifact's type, for the listing.
    pub artifact_type: String,
}

/// The result of promoting a personal mark to the shared set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionOutcome {
    /// A shared bookmark was created with the personal note; its id.
    Promoted(Uuid),
    /// No such personal mark owned by this user in this case.
    NotFound,
    /// Already promoted, to this shared bookmark.
    AlreadyPromoted(Uuid),
    /// The artifact already has a shared bookmark (one per artifact per case,
    /// migration 0009). Promotion is refused rather than overwriting a
    /// colleague's shared note with this private one.
    SharedBookmarkExists(Uuid),
}

impl SqliteConnection {
    /// Record an assignment of `artifact_ids` in `case_id` to
    /// `assignee_user_id`, atomically.
    ///
    /// Duplicate ids are collapsed. An id that is not an artifact of this case
    /// refuses the whole request and writes nothing: the foreign key alone
    /// would accept an artifact from another case.
    ///
    /// Whether the assignee may review in this case (read_write or owner) is
    /// the API's check, not this layer's, because admins bypass `case_access`.
    pub async fn create_assignment(
        &self,
        case_id: Uuid,
        assignee_user_id: Uuid,
        assigned_by: Option<Uuid>,
        note: Option<&str>,
        due_at: Option<i64>,
        artifact_ids: &[Uuid],
    ) -> Result<std::result::Result<Uuid, AssignmentRefusal>> {
        if artifact_ids.is_empty() {
            return Ok(Err(AssignmentRefusal::Empty));
        }
        if artifact_ids.len() > ASSIGNMENT_ITEMS_MAX {
            return Ok(Err(AssignmentRefusal::OverCap(artifact_ids.len())));
        }
        let mut unique: Vec<Uuid> = artifact_ids.to_vec();
        unique.sort();
        unique.dedup();

        let case_bytes = case_id.as_bytes().to_vec();
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to open a transaction for an assignment")?;

        // The case-scoping gate, per id, before anything is written.
        let mut not_in_case = Vec::new();
        for id in &unique {
            let in_case: Option<(i64,)> =
                sqlx::query_as("SELECT 1 FROM artifacts WHERE id = ? AND case_id = ?")
                    .bind(id.as_bytes().to_vec())
                    .bind(&case_bytes)
                    .fetch_optional(&mut *tx)
                    .await
                    .context("Failed to verify an assigned artifact's case")?;
            if in_case.is_none() {
                not_in_case.push(*id);
            }
        }
        if !not_in_case.is_empty() {
            // Dropping the transaction rolls it back; nothing was written.
            return Ok(Err(AssignmentRefusal::NotInCase(not_in_case)));
        }

        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO case_assignments \
                 (id, case_id, assignee_user_id, assigned_by, note, created_at, due_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(case_id)
        .bind(assignee_user_id)
        .bind(assigned_by)
        .bind(note)
        .bind(Utc::now().timestamp())
        .bind(due_at)
        .execute(&mut *tx)
        .await
        .context("Failed to record an assignment")?;

        for artifact_id in &unique {
            sqlx::query(
                "INSERT INTO case_assignment_items (assignment_id, artifact_id) VALUES (?, ?)",
            )
            .bind(id)
            .bind(artifact_id)
            .execute(&mut *tx)
            .await
            .context("Failed to record an assigned artifact")?;
        }
        tx.commit()
            .await
            .context("Failed to commit an assignment")?;
        Ok(Ok(id))
    }

    /// Move an active assignment to another examiner, atomically: the old one
    /// is withdrawn (kept, marked) and a new one is recorded over the same
    /// items with `reassigned_from` set. Whether the new assignee may review
    /// in this case is the API's check, as for [`Self::create_assignment`].
    pub async fn reassign_assignment(
        &self,
        case_id: Uuid,
        from_assignment_id: Uuid,
        assignee_user_id: Uuid,
        acting_user_id: Option<Uuid>,
        note: Option<&str>,
        due_at: Option<i64>,
    ) -> Result<std::result::Result<Uuid, ReassignRefusal>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to open a transaction to reassign")?;
        let withdrawn_at: Option<(Option<i64>,)> = sqlx::query_as(
            "SELECT withdrawn_at FROM case_assignments WHERE case_id = ? AND id = ?",
        )
        .bind(case_id)
        .bind(from_assignment_id)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to read the assignment to reassign")?;
        match withdrawn_at {
            None => return Ok(Err(ReassignRefusal::NotFound)),
            Some((Some(_),)) => return Ok(Err(ReassignRefusal::AlreadyWithdrawn)),
            Some((None,)) => {}
        }
        let now = Utc::now().timestamp();
        sqlx::query(
            "UPDATE case_assignments SET withdrawn_at = ?, withdrawn_by = ? \
             WHERE id = ? AND withdrawn_at IS NULL",
        )
        .bind(now)
        .bind(acting_user_id)
        .bind(from_assignment_id)
        .execute(&mut *tx)
        .await
        .context("Failed to withdraw the assignment being reassigned")?;
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO case_assignments \
                 (id, case_id, assignee_user_id, assigned_by, note, created_at, due_at, \
                  reassigned_from) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(case_id)
        .bind(assignee_user_id)
        .bind(acting_user_id)
        .bind(note)
        .bind(now)
        .bind(due_at)
        .bind(from_assignment_id)
        .execute(&mut *tx)
        .await
        .context("Failed to record the reassignment")?;
        sqlx::query(
            "INSERT INTO case_assignment_items (assignment_id, artifact_id) \
             SELECT ?, artifact_id FROM case_assignment_items WHERE assignment_id = ?",
        )
        .bind(id)
        .bind(from_assignment_id)
        .execute(&mut *tx)
        .await
        .context("Failed to copy the reassigned items")?;
        tx.commit()
            .await
            .context("Failed to commit the reassignment")?;
        Ok(Ok(id))
    }

    const ASSIGNMENT_SELECT: &'static str = "SELECT a.id, a.case_id, a.assignee_user_id, \
                u.username AS assignee_username, a.assigned_by, a.note, a.created_at, \
                a.withdrawn_at, a.withdrawn_by, a.due_at, a.reassigned_from, \
                (SELECT COUNT(*) FROM case_assignment_items i WHERE i.assignment_id = a.id) \
                    AS item_count \
         FROM case_assignments a \
         INNER JOIN users u ON u.id = a.assignee_user_id";

    fn decode_assignment(row: &sqlx::sqlite::SqliteRow) -> Result<CaseAssignment> {
        let uuid = |col: &str| -> Result<Uuid> {
            let b: Vec<u8> = row.try_get(col)?;
            Uuid::from_slice(&b).with_context(|| format!("Invalid UUID in {col}"))
        };
        let opt_uuid = |col: &str| -> Result<Option<Uuid>> {
            let b: Option<Vec<u8>> = row.try_get(col)?;
            b.map(|b| Uuid::from_slice(&b))
                .transpose()
                .with_context(|| format!("Invalid UUID in {col}"))
        };
        Ok(CaseAssignment {
            id: uuid("id")?,
            case_id: uuid("case_id")?,
            assignee_user_id: uuid("assignee_user_id")?,
            assignee_username: row.try_get("assignee_username")?,
            assigned_by: opt_uuid("assigned_by")?,
            note: row.try_get("note")?,
            created_at: row.try_get("created_at")?,
            withdrawn_at: row.try_get("withdrawn_at")?,
            withdrawn_by: opt_uuid("withdrawn_by")?,
            due_at: row.try_get("due_at")?,
            reassigned_from: opt_uuid("reassigned_from")?,
            item_count: row.try_get("item_count")?,
        })
    }

    /// Every assignment in a case, active and withdrawn, newest first.
    pub async fn list_assignments(&self, case_id: Uuid) -> Result<Vec<CaseAssignment>> {
        let sql = format!(
            "{} WHERE a.case_id = ? ORDER BY a.created_at DESC, a.id DESC",
            Self::ASSIGNMENT_SELECT
        );
        let rows = sqlx::query(&sql)
            .bind(case_id)
            .fetch_all(&self.pool)
            .await
            .context("Failed to list assignments")?;
        rows.iter().map(Self::decode_assignment).collect()
    }

    /// One assignment, scoped to its case.
    pub async fn get_assignment(
        &self,
        case_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<Option<CaseAssignment>> {
        let sql = format!(
            "{} WHERE a.case_id = ? AND a.id = ?",
            Self::ASSIGNMENT_SELECT
        );
        let row = sqlx::query(&sql)
            .bind(case_id)
            .bind(assignment_id)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to read an assignment")?;
        row.as_ref().map(Self::decode_assignment).transpose()
    }

    /// Withdraw an active assignment. Returns `false` when there is no such
    /// assignment in this case or it was already withdrawn. The row and its
    /// items are kept.
    pub async fn withdraw_assignment(
        &self,
        case_id: Uuid,
        assignment_id: Uuid,
        withdrawn_by: Option<Uuid>,
    ) -> Result<bool> {
        let done = sqlx::query(
            "UPDATE case_assignments SET withdrawn_at = ?, withdrawn_by = ? \
             WHERE case_id = ? AND id = ? AND withdrawn_at IS NULL",
        )
        .bind(Utc::now().timestamp())
        .bind(withdrawn_by)
        .bind(case_id)
        .bind(assignment_id)
        .execute(&self.pool)
        .await
        .context("Failed to withdraw an assignment")?;
        Ok(done.rows_affected() == 1)
    }

    /// Progress of an assignment, counting only the assignee's own ledger
    /// rows.
    pub async fn assignment_progress(&self, assignment_id: Uuid) -> Result<AssignmentProgress> {
        let row: Option<(i64, i64, i64)> = sqlx::query_as(
            "SELECT COUNT(*), \
                    COUNT(r.artifact_id), \
                    COUNT(r.reviewed_at) \
             FROM case_assignments a \
             INNER JOIN users u ON u.id = a.assignee_user_id \
             INNER JOIN case_assignment_items i ON i.assignment_id = a.id \
             LEFT JOIN artifact_reviews r \
                 ON r.case_id = a.case_id AND r.artifact_id = i.artifact_id \
                AND r.examiner = u.username \
             WHERE a.id = ?",
        )
        .bind(assignment_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to read assignment progress")?;
        let (total, opened, reviewed) = row.unwrap_or((0, 0, 0));
        Ok(AssignmentProgress {
            total,
            opened_by_assignee: opened,
            reviewed_by_assignee: reviewed,
        })
    }

    /// The assigned items the assignee has NOT reviewed, one page, in
    /// artifact-id order. A colleague's review does not remove an item.
    pub async fn assignment_queue(
        &self,
        assignment_id: Uuid,
        limit: Option<usize>,
        offset: usize,
    ) -> Result<BoundedList<AssignmentQueueItem>> {
        let limit = clamp_page_size(limit, ASSIGNMENT_QUEUE_PAGE_MAX);
        let mut rows: Vec<(Vec<u8>, String, Option<i64>)> = sqlx::query_as(
            "SELECT i.artifact_id, art.artifact_type, r.opened_at \
             FROM case_assignments a \
             INNER JOIN users u ON u.id = a.assignee_user_id \
             INNER JOIN case_assignment_items i ON i.assignment_id = a.id \
             INNER JOIN artifacts art ON art.id = i.artifact_id \
             LEFT JOIN artifact_reviews r \
                 ON r.case_id = a.case_id AND r.artifact_id = i.artifact_id \
                AND r.examiner = u.username \
             WHERE a.id = ? AND r.reviewed_at IS NULL \
             ORDER BY i.artifact_id LIMIT ? OFFSET ?",
        )
        .bind(assignment_id)
        .bind(probe_limit(limit))
        .bind(i64::try_from(offset).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .context("Failed to read an assignment queue")?;
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let mut undecodable = 0;
        let mut items = Vec::with_capacity(rows.len());
        for (id, artifact_type, opened_at) in rows {
            match Uuid::from_slice(&id) {
                Ok(artifact_id) => items.push(AssignmentQueueItem {
                    artifact_id,
                    artifact_type,
                    opened_at,
                }),
                Err(_) => undecodable += 1,
            }
        }
        Ok(BoundedList {
            items,
            limit,
            offset,
            has_more,
            undecodable,
        })
    }
}

impl SqliteConnection {
    /// Create or update the owner's personal mark on an artifact. Returns
    /// `None` when the artifact is not in this case (nothing written). A
    /// repeat keeps the mark's id and `created_at`; a `None` note leaves the
    /// stored note alone.
    pub async fn upsert_personal_bookmark(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        owner_user_id: Uuid,
        note: Option<&str>,
    ) -> Result<Option<Uuid>> {
        let in_case: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM artifacts WHERE id = ? AND case_id = ?")
                .bind(artifact_id)
                .bind(case_id)
                .fetch_optional(&self.pool)
                .await
                .context("Failed to verify a personal bookmark's case")?;
        if in_case.is_none() {
            return Ok(None);
        }
        let now = Utc::now().timestamp();
        let id: Vec<u8> = sqlx::query_scalar(
            "INSERT INTO personal_bookmarks \
                 (id, case_id, artifact_id, owner_user_id, note, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(case_id, artifact_id, owner_user_id) DO UPDATE SET \
                 note = COALESCE(excluded.note, personal_bookmarks.note), \
                 updated_at = excluded.updated_at \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(case_id)
        .bind(artifact_id)
        .bind(owner_user_id)
        .bind(note)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .context("Failed to write a personal bookmark")?;
        Ok(Some(
            Uuid::from_slice(&id).context("Invalid personal bookmark id")?,
        ))
    }

    /// One page of the owner's personal marks in a case, newest-touched
    /// first. Nobody else's marks are ever returned.
    pub async fn list_personal_bookmarks(
        &self,
        case_id: Uuid,
        owner_user_id: Uuid,
        limit: Option<usize>,
        offset: usize,
    ) -> Result<BoundedList<PersonalBookmark>> {
        let limit = clamp_page_size(limit, PERSONAL_BOOKMARK_PAGE_MAX);
        let mut rows = sqlx::query(
            "SELECT p.id, p.case_id, p.artifact_id, p.owner_user_id, p.note, p.created_at, \
                    p.updated_at, p.promoted_at, p.promoted_bookmark_id, a.artifact_type, \
                    EXISTS (SELECT 1 FROM artifact_bookmarks b \
                            WHERE b.id = p.promoted_bookmark_id) AS in_shared_set \
             FROM personal_bookmarks p \
             INNER JOIN artifacts a ON a.id = p.artifact_id AND a.case_id = p.case_id \
             WHERE p.case_id = ? AND p.owner_user_id = ? \
             ORDER BY p.updated_at DESC, p.id DESC LIMIT ? OFFSET ?",
        )
        .bind(case_id)
        .bind(owner_user_id)
        .bind(probe_limit(limit))
        .bind(i64::try_from(offset).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .context("Failed to list personal bookmarks")?;
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let decode = |row: &sqlx::sqlite::SqliteRow| -> Result<PersonalBookmark> {
            let uuid = |col: &str| -> Result<Uuid> {
                let b: Vec<u8> = row.try_get(col)?;
                Ok(Uuid::from_slice(&b)?)
            };
            let promoted: Option<Vec<u8>> = row.try_get("promoted_bookmark_id")?;
            Ok(PersonalBookmark {
                id: uuid("id")?,
                case_id: uuid("case_id")?,
                artifact_id: uuid("artifact_id")?,
                owner_user_id: uuid("owner_user_id")?,
                note: row.try_get("note")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
                promoted_at: row.try_get("promoted_at")?,
                promoted_bookmark_id: promoted.map(|b| Uuid::from_slice(&b)).transpose()?,
                in_shared_set: row.try_get::<i64, _>("in_shared_set")? != 0,
                artifact_type: row.try_get("artifact_type")?,
            })
        };
        let mut undecodable = 0;
        let mut items = Vec::with_capacity(rows.len());
        for row in &rows {
            match decode(row) {
                Ok(b) => items.push(b),
                Err(_) => undecodable += 1,
            }
        }
        Ok(BoundedList {
            items,
            limit,
            offset,
            has_more,
            undecodable,
        })
    }

    /// Delete one of the owner's personal marks. `false` if it is not theirs
    /// or does not exist. Deleting a promoted mark leaves the shared bookmark
    /// it became untouched.
    pub async fn delete_personal_bookmark(
        &self,
        case_id: Uuid,
        owner_user_id: Uuid,
        id: Uuid,
    ) -> Result<bool> {
        let done = sqlx::query(
            "DELETE FROM personal_bookmarks WHERE case_id = ? AND owner_user_id = ? AND id = ?",
        )
        .bind(case_id)
        .bind(owner_user_id)
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to delete a personal bookmark")?;
        Ok(done.rows_affected() == 1)
    }

    /// Promote one of the owner's personal marks into the shared set, which is
    /// what the report reads. Refused, not merged, when the artifact already
    /// carries a shared bookmark: that bookmark's note is a colleague's
    /// recorded finding and a promotion must not overwrite it.
    pub async fn promote_personal_bookmark(
        &self,
        case_id: Uuid,
        owner_user_id: Uuid,
        id: Uuid,
        examiner: &str,
    ) -> Result<PromotionOutcome> {
        let mut tx = self
            .pool
            // IMMEDIATE: take the write lock before the existence check, so a
            // concurrent promotion waits and then sees the shared bookmark,
            // instead of both passing the check and one failing the UNIQUE
            // constraint (or a deferred upgrade failing with BUSY_SNAPSHOT).
            .begin_with("BEGIN IMMEDIATE")
            .await
            .context("Failed to open a transaction for a promotion")?;
        let mark: Option<(Vec<u8>, Option<String>, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT artifact_id, note, promoted_bookmark_id FROM personal_bookmarks \
             WHERE case_id = ? AND owner_user_id = ? AND id = ?",
        )
        .bind(case_id)
        .bind(owner_user_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to read a personal bookmark")?;
        let Some((artifact_bytes, note, promoted)) = mark else {
            return Ok(PromotionOutcome::NotFound);
        };
        if let Some(b) = promoted {
            // Only "already promoted" while the shared bookmark still exists;
            // one deleted since may be promoted again.
            let live: Option<(i64,)> =
                sqlx::query_as("SELECT 1 FROM artifact_bookmarks WHERE id = ?")
                    .bind(&b)
                    .fetch_optional(&mut *tx)
                    .await
                    .context("Failed to check a promoted bookmark")?;
            if live.is_some() {
                return Ok(PromotionOutcome::AlreadyPromoted(Uuid::from_slice(&b)?));
            }
        }
        let existing: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT id FROM artifact_bookmarks WHERE case_id = ? AND artifact_id = ?",
        )
        .bind(case_id)
        .bind(&artifact_bytes)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to check for a shared bookmark")?;
        if let Some(b) = existing {
            return Ok(PromotionOutcome::SharedBookmarkExists(Uuid::from_slice(
                &b,
            )?));
        }
        let now = Utc::now().timestamp();
        let shared = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO artifact_bookmarks \
                 (id, case_id, artifact_id, category_id, note, examiner, created_at, updated_at) \
             VALUES (?, ?, ?, NULL, ?, ?, ?, ?)",
        )
        .bind(shared)
        .bind(case_id)
        .bind(&artifact_bytes)
        .bind(note)
        .bind(examiner)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await
        .context("Failed to write the promoted shared bookmark")?;
        sqlx::query(
            "UPDATE personal_bookmarks SET promoted_at = ?, promoted_bookmark_id = ? WHERE id = ?",
        )
        .bind(now)
        .bind(shared)
        .bind(id)
        .execute(&mut *tx)
        .await
        .context("Failed to record the promotion")?;
        tx.commit().await.context("Failed to commit a promotion")?;
        Ok(PromotionOutcome::Promoted(shared))
    }

    /// How many personal marks in a case are NOT in the shared set — the
    /// count a report states as excluded.
    pub async fn count_unpromoted_personal_bookmarks(&self, case_id: Uuid) -> Result<i64> {
        sqlx::query_scalar(
            // A promoted mark whose shared bookmark was later deleted is no
            // longer in the report, so it is counted as excluded again.
            "SELECT COUNT(*) FROM personal_bookmarks p WHERE p.case_id = ? \
               AND NOT EXISTS (SELECT 1 FROM artifact_bookmarks b \
                               WHERE b.id = p.promoted_bookmark_id)",
        )
        .bind(case_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count personal bookmarks")
    }
}

#[cfg(test)]
mod assignment_tests {
    use super::*;
    use seance_core::artifact::{Artifact, ArtifactType};
    use serde_json::json;

    async fn test_db() -> SqliteConnection {
        let db = SqliteConnection::new("sqlite::memory:").await.unwrap();
        db.initialize().await.unwrap();
        db
    }

    async fn artifacts(db: &SqliteConnection, case_id: Uuid, n: usize) -> Vec<Uuid> {
        let mut ids = Vec::new();
        for i in 0..n {
            let a = Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                json!({ "name": format!("f{i}.bin") }),
            );
            db.record_artifact(&a).await.unwrap();
            ids.push(a.id);
        }
        ids
    }

    async fn user(db: &SqliteConnection, name: &str) -> Uuid {
        db.create_user(name, "$2b$12$not-a-real-hash", "examiner")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn reassigning_keeps_the_old_assignment_and_copies_its_items_atomically() {
        let db = test_db().await;
        let case_id = db.create_case("Assign", "e").await.unwrap();
        let ids = artifacts(&db, case_id, 3).await;
        let alice = user(&db, "alice").await;
        let bob = user(&db, "bob").await;
        let old = db
            .create_assignment(
                case_id,
                alice,
                None,
                Some("triage"),
                Some(4_000_000_000),
                &ids,
            )
            .await
            .unwrap()
            .unwrap();

        let new = db
            .reassign_assignment(case_id, old, bob, None, Some("alice is out"), None)
            .await
            .unwrap()
            .expect("an active assignment can be reassigned");

        let old_row = db.get_assignment(case_id, old).await.unwrap().unwrap();
        let new_row = db.get_assignment(case_id, new).await.unwrap().unwrap();
        assert!(
            old_row.withdrawn_at.is_some(),
            "the old one is kept, marked"
        );
        assert_eq!(old_row.item_count, 3, "and keeps its items");
        assert_eq!(old_row.due_at, Some(4_000_000_000));
        assert_eq!(new_row.item_count, 3);
        assert_eq!(new_row.assignee_user_id, bob);
        assert_eq!(new_row.reassigned_from, Some(old));
        assert_eq!(
            new_row.due_at, None,
            "the due date is not inherited silently"
        );

        // The source is withdrawn now: a second reassignment writes nothing.
        assert_eq!(
            db.reassign_assignment(case_id, old, alice, None, None, None)
                .await
                .unwrap(),
            Err(ReassignRefusal::AlreadyWithdrawn)
        );
        assert_eq!(
            db.reassign_assignment(case_id, Uuid::new_v4(), alice, None, None, None)
                .await
                .unwrap(),
            Err(ReassignRefusal::NotFound)
        );
        assert_eq!(db.list_assignments(case_id).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_assignments_progress_counts_only_the_assignees_reviews() {
        let db = test_db().await;
        let case_id = db.create_case("Assign", "e").await.unwrap();
        let ids = artifacts(&db, case_id, 3).await;
        let alice = user(&db, "alice").await;

        let assignment = db
            .create_assignment(case_id, alice, None, Some("triage"), None, &ids)
            .await
            .unwrap()
            .expect("three artifacts of this case are assignable");

        // Bob reviews item 0: a colleague's work, not alice's.
        db.record_artifact_reviews(case_id, "bob", &[(ids[0], ReviewMark::Reviewed)])
            .await
            .unwrap();
        // Alice opens item 1 and reviews item 2.
        db.record_artifact_reviews(
            case_id,
            "alice",
            &[(ids[1], ReviewMark::Opened), (ids[2], ReviewMark::Reviewed)],
        )
        .await
        .unwrap();

        let p = db.assignment_progress(assignment).await.unwrap();
        assert_eq!(
            p,
            AssignmentProgress {
                total: 3,
                opened_by_assignee: 2,
                reviewed_by_assignee: 1
            },
            "only the assignee's own ledger rows count"
        );

        // The queue is the assigned items alice has not reviewed; bob's review
        // of item 0 does not remove it.
        let q = db.assignment_queue(assignment, None, 0).await.unwrap();
        let mut left: Vec<Uuid> = q.items.iter().map(|i| i.artifact_id).collect();
        left.sort();
        let mut want = vec![ids[0], ids[1]];
        want.sort();
        assert_eq!(left, want);
        assert!(q.is_complete());
        let opened = q.items.iter().find(|i| i.artifact_id == ids[1]).unwrap();
        assert!(opened.opened_at.is_some(), "alice's opening is shown");
        let untouched = q.items.iter().find(|i| i.artifact_id == ids[0]).unwrap();
        assert_eq!(untouched.opened_at, None, "bob's opening is not alice's");
    }

    #[tokio::test]
    async fn an_assignment_refuses_an_artifact_from_another_case() {
        let db = test_db().await;
        let case_a = db.create_case("A", "e").await.unwrap();
        let case_b = db.create_case("B", "e").await.unwrap();
        let in_a = artifacts(&db, case_a, 1).await;
        let in_b = artifacts(&db, case_b, 1).await;
        let alice = user(&db, "alice").await;

        let refused = db
            .create_assignment(case_a, alice, None, None, None, &[in_a[0], in_b[0]])
            .await
            .unwrap();
        assert_eq!(refused, Err(AssignmentRefusal::NotInCase(vec![in_b[0]])));

        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM case_assignments")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        let m: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM case_assignment_items")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!((n, m), (0, 0), "a refused assignment writes nothing");

        assert_eq!(
            db.create_assignment(case_a, alice, None, None, None, &[])
                .await
                .unwrap(),
            Err(AssignmentRefusal::Empty)
        );
        let over = vec![in_a[0]; ASSIGNMENT_ITEMS_MAX + 1];
        assert_eq!(
            db.create_assignment(case_a, alice, None, None, None, &over)
                .await
                .unwrap(),
            Err(AssignmentRefusal::OverCap(ASSIGNMENT_ITEMS_MAX + 1))
        );
    }

    #[tokio::test]
    async fn a_withdrawn_assignment_keeps_its_items_and_says_when() {
        let db = test_db().await;
        let case_id = db.create_case("W", "e").await.unwrap();
        let ids = artifacts(&db, case_id, 2).await;
        let alice = user(&db, "alice").await;
        let owner = user(&db, "olive").await;
        let a = db
            .create_assignment(case_id, alice, Some(owner), None, None, &ids)
            .await
            .unwrap()
            .unwrap();

        assert!(db
            .withdraw_assignment(case_id, a, Some(owner))
            .await
            .unwrap());
        assert!(
            !db.withdraw_assignment(case_id, a, Some(owner))
                .await
                .unwrap(),
            "a second withdrawal changes nothing"
        );

        let list = db.list_assignments(case_id).await.unwrap();
        assert_eq!(list.len(), 1, "a withdrawal is recorded, never deleted");
        let got = &list[0];
        assert_eq!(got.id, a);
        assert!(got.withdrawn_at.is_some());
        assert_eq!(got.withdrawn_by, Some(owner));
        assert_eq!(got.item_count, 2, "the items survive the withdrawal");
        assert_eq!(got.assignee_username, "alice");
        assert_eq!(got.assigned_by, Some(owner));

        // Scoped to its case: another case cannot see or withdraw it.
        let other = db.create_case("Other", "e").await.unwrap();
        assert!(db.get_assignment(other, a).await.unwrap().is_none());
        assert!(db.get_assignment(case_id, a).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn deleting_the_assignee_user_cascades_the_assignment() {
        let db = test_db().await;
        let case_id = db.create_case("D", "e").await.unwrap();
        let ids = artifacts(&db, case_id, 1).await;
        let alice = user(&db, "alice").await;
        db.create_assignment(case_id, alice, None, None, None, &ids)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(db.list_assignments(case_id).await.unwrap().len(), 1);

        assert!(db.delete_user(alice).await.unwrap());
        assert!(db.list_assignments(case_id).await.unwrap().is_empty());
        let m: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM case_assignment_items")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(m, 0);
    }
    #[tokio::test]
    async fn a_personal_mark_is_seen_only_by_its_owner_and_never_in_the_shared_set() {
        let db = test_db().await;
        let case_id = db.create_case("P", "e").await.unwrap();
        let ids = artifacts(&db, case_id, 2).await;
        let alice = user(&db, "alice").await;
        let bob = user(&db, "bob").await;

        let mark = db
            .upsert_personal_bookmark(case_id, ids[0], alice, Some("maybe"))
            .await
            .unwrap()
            .expect("an artifact of this case can be marked");
        // A repeat keeps the id and moves the note.
        let again = db
            .upsert_personal_bookmark(case_id, ids[0], alice, Some("probably"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mark, again);

        let mine = db
            .list_personal_bookmarks(case_id, alice, None, 0)
            .await
            .unwrap();
        assert_eq!(mine.items.len(), 1);
        assert_eq!(mine.items[0].note.as_deref(), Some("probably"));
        assert!(db
            .list_personal_bookmarks(case_id, bob, None, 0)
            .await
            .unwrap()
            .items
            .is_empty());

        // The shared set (what the report reads) does not contain it.
        let shared = db
            .list_artifact_bookmarks(case_id, None, None, 0)
            .await
            .unwrap();
        assert!(shared.items.is_empty());
        assert_eq!(
            db.count_unpromoted_personal_bookmarks(case_id)
                .await
                .unwrap(),
            1
        );

        // Another case's artifact is refused.
        let other = db.create_case("O", "e").await.unwrap();
        assert!(db
            .upsert_personal_bookmark(other, ids[1], alice, None)
            .await
            .unwrap()
            .is_none());

        // Bob cannot delete alice's mark; alice can.
        assert!(!db
            .delete_personal_bookmark(case_id, bob, mark)
            .await
            .unwrap());
        assert!(db
            .delete_personal_bookmark(case_id, alice, mark)
            .await
            .unwrap());
        assert_eq!(
            db.count_unpromoted_personal_bookmarks(case_id)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn promoting_a_personal_mark_creates_one_shared_bookmark_and_never_overwrites() {
        let db = test_db().await;
        let case_id = db.create_case("P", "e").await.unwrap();
        let ids = artifacts(&db, case_id, 2).await;
        let alice = user(&db, "alice").await;
        let bob = user(&db, "bob").await;

        let mark = db
            .upsert_personal_bookmark(case_id, ids[0], alice, Some("contraband"))
            .await
            .unwrap()
            .unwrap();
        // Bob cannot promote alice's mark.
        assert_eq!(
            db.promote_personal_bookmark(case_id, bob, mark, "bob")
                .await
                .unwrap(),
            PromotionOutcome::NotFound
        );
        let shared_id = match db
            .promote_personal_bookmark(case_id, alice, mark, "alice")
            .await
            .unwrap()
        {
            PromotionOutcome::Promoted(id) => id,
            other => panic!("expected promotion, got {other:?}"),
        };
        let shared = db
            .get_artifact_bookmark(case_id, ids[0])
            .await
            .unwrap()
            .expect("promotion writes the shared bookmark");
        assert_eq!(shared.id, shared_id);
        assert_eq!(shared.note.as_deref(), Some("contraband"));
        assert_eq!(shared.examiner.as_deref(), Some("alice"));
        assert_eq!(
            db.promote_personal_bookmark(case_id, alice, mark, "alice")
                .await
                .unwrap(),
            PromotionOutcome::AlreadyPromoted(shared_id)
        );
        assert_eq!(
            db.count_unpromoted_personal_bookmarks(case_id)
                .await
                .unwrap(),
            0,
            "a promoted mark is in the report and is not counted as excluded"
        );

        // A shared bookmark by bob already exists on ids[1]: alice's promotion
        // is refused and bob's note stands.
        let bobs = db
            .create_artifact_bookmark(case_id, ids[1], None, Some("bob's note"), Some("bob"))
            .await
            .unwrap();
        let alices = db
            .upsert_personal_bookmark(case_id, ids[1], alice, Some("alice's note"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            db.promote_personal_bookmark(case_id, alice, alices, "alice")
                .await
                .unwrap(),
            PromotionOutcome::SharedBookmarkExists(bobs)
        );
        let kept = db
            .get_artifact_bookmark(case_id, ids[1])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kept.note.as_deref(), Some("bob's note"));
        assert_eq!(
            db.count_unpromoted_personal_bookmarks(case_id)
                .await
                .unwrap(),
            1
        );
    }
    #[tokio::test]
    async fn a_promoted_mark_whose_shared_bookmark_was_deleted_counts_as_excluded_again() {
        let db = test_db().await;
        let case_id = db.create_case("P", "e").await.unwrap();
        let ids = artifacts(&db, case_id, 1).await;
        let alice = user(&db, "alice").await;
        let mark = db
            .upsert_personal_bookmark(case_id, ids[0], alice, Some("n"))
            .await
            .unwrap()
            .unwrap();
        let PromotionOutcome::Promoted(_) = db
            .promote_personal_bookmark(case_id, alice, mark, "alice")
            .await
            .unwrap()
        else {
            panic!("expected promotion")
        };
        let listed = db
            .list_personal_bookmarks(case_id, alice, None, 0)
            .await
            .unwrap();
        assert!(listed.items[0].in_shared_set, "promoted and live");
        sqlx::query("DELETE FROM artifact_bookmarks")
            .execute(&db.pool)
            .await
            .unwrap();
        assert_eq!(
            db.count_unpromoted_personal_bookmarks(case_id)
                .await
                .unwrap(),
            1,
            "a mark not in the report must be counted as excluded"
        );
        // The owner's listing must say the same thing the report count does:
        // a mark whose shared bookmark is gone is not in the shared set.
        let listed = db
            .list_personal_bookmarks(case_id, alice, None, 0)
            .await
            .unwrap();
        assert!(listed.items[0].promoted_at.is_some());
        assert!(
            !listed.items[0].in_shared_set,
            "a promoted mark whose shared bookmark was deleted is not in the shared set"
        );
        assert!(matches!(
            db.promote_personal_bookmark(case_id, alice, mark, "alice")
                .await
                .unwrap(),
            PromotionOutcome::Promoted(_)
        ));
    }

    #[tokio::test]
    async fn assignment_queue_pages_with_has_more() {
        let db = test_db().await;
        let case_id = db.create_case("Q", "e").await.unwrap();
        let ids = artifacts(&db, case_id, 3).await;
        let alice = user(&db, "alice").await;
        let a = db
            .create_assignment(case_id, alice, None, None, None, &ids)
            .await
            .unwrap()
            .unwrap();

        let first = db.assignment_queue(a, Some(2), 0).await.unwrap();
        assert_eq!(first.items.len(), 2);
        assert!(first.has_more);
        let second = db.assignment_queue(a, Some(2), 2).await.unwrap();
        assert_eq!(second.items.len(), 1);
        assert!(!second.has_more);
        assert_eq!(second.offset, 2);
        let mut seen: Vec<Uuid> = first
            .items
            .iter()
            .chain(&second.items)
            .map(|i| i.artifact_id)
            .collect();
        seen.sort();
        let mut want = ids.clone();
        want.sort();
        assert_eq!(seen, want, "every item exactly once across the pages");
    }

    #[tokio::test]
    async fn list_personal_bookmarks_pages_with_has_more() {
        let db = test_db().await;
        let case_id = db.create_case("B", "e").await.unwrap();
        let ids = artifacts(&db, case_id, 3).await;
        let alice = user(&db, "alice").await;
        for id in &ids {
            db.upsert_personal_bookmark(case_id, *id, alice, None)
                .await
                .unwrap()
                .unwrap();
        }
        let first = db
            .list_personal_bookmarks(case_id, alice, Some(2), 0)
            .await
            .unwrap();
        assert_eq!(first.items.len(), 2);
        assert!(first.has_more);
        let second = db
            .list_personal_bookmarks(case_id, alice, Some(2), 2)
            .await
            .unwrap();
        assert_eq!(second.items.len(), 1);
        assert!(!second.has_more);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_promotions_of_one_artifact_refuse_the_loser_cleanly() {
        let path = format!(
            "{}/seance_promote_{}.db",
            std::env::temp_dir().display(),
            Uuid::new_v4().simple()
        );
        let db = SqliteConnection::new(&format!("sqlite:{path}?mode=rwc"))
            .await
            .unwrap();
        db.initialize().await.unwrap();
        let case_id = db.create_case("P", "e").await.unwrap();
        let ids = artifacts(&db, case_id, 1).await;
        let alice = user(&db, "alice").await;
        let bob = user(&db, "bob").await;
        let a = db
            .upsert_personal_bookmark(case_id, ids[0], alice, None)
            .await
            .unwrap()
            .unwrap();
        let b = db
            .upsert_personal_bookmark(case_id, ids[0], bob, None)
            .await
            .unwrap()
            .unwrap();
        let (d1, d2) = (db.clone(), db.clone());
        let t1 = tokio::spawn(async move {
            d1.promote_personal_bookmark(case_id, alice, a, "alice")
                .await
        });
        let t2 =
            tokio::spawn(async move { d2.promote_personal_bookmark(case_id, bob, b, "bob").await });
        let outcomes = [t1.await.unwrap().unwrap(), t2.await.unwrap().unwrap()];
        let promoted = outcomes
            .iter()
            .filter(|o| matches!(o, PromotionOutcome::Promoted(_)))
            .count();
        let refused = outcomes
            .iter()
            .filter(|o| matches!(o, PromotionOutcome::SharedBookmarkExists(_)))
            .count();
        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
        assert_eq!((promoted, refused), (1, 1), "{outcomes:?}");
    }
}
