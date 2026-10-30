//! Nested bookmark folders (ROADMAP §3.15).
//!
//! A folder is a `bookmark_categories` row; `parent_id` (migration 0046) puts it
//! under another folder of the **same case**. Three rules are enforced here
//! because SQLite cannot express them and a refusal has to name the one broken:
//!
//! * the parent exists and belongs to this case — a folder under another case's
//!   folder would be deleted from underneath it and would leak a name across
//!   cases;
//! * no cycle — a folder under its own descendant would be unreachable from the
//!   top level;
//! * a depth bound ([`CATEGORY_DEPTH_MAX`]) — the tree is walked, and an
//!   unbounded chain is a walk with no end.

use super::*;

/// Most levels a folder tree may have (a top-level folder is level 1).
pub const CATEGORY_DEPTH_MAX: usize = 5;

/// Why a folder could not be created or moved. Nothing was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderRefusal {
    /// The named parent does not exist, or belongs to another case.
    ParentNotInCase,
    /// The folder being moved does not exist in this case.
    NotFound,
    /// The move would put a folder under itself or one of its descendants.
    Cycle,
    /// The result would be deeper than [`CATEGORY_DEPTH_MAX`] levels.
    TooDeep,
}

impl SqliteConnection {
    /// The parent of a folder in `case_id`: `None` when the folder is not in the
    /// case, `Some(None)` at the top level.
    async fn folder_parent(
        conn: &mut sqlx::SqliteConnection,
        case_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Option<Uuid>>> {
        let row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
            "SELECT parent_id FROM bookmark_categories WHERE id = ? AND case_id = ?",
        )
        .bind(id)
        .bind(case_id)
        .fetch_optional(&mut *conn)
        .await
        .context("Failed to read a bookmark folder's parent")?;
        row.map(|(p,)| {
            p.map(|p| Uuid::from_slice(&p))
                .transpose()
                .context("Invalid folder parent id")
        })
        .transpose()
    }

    /// The folders from `id` up to the top level, `id` first. `None` when `id` is
    /// not a folder of this case. Stops at [`CATEGORY_DEPTH_MAX`] + 1 so a damaged
    /// tree that loops cannot hang the walk.
    async fn folder_chain(
        conn: &mut sqlx::SqliteConnection,
        case_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Vec<Uuid>>> {
        let mut chain = vec![id];
        let mut current = id;
        loop {
            let Some(parent) = Self::folder_parent(conn, case_id, current).await? else {
                return Ok(None);
            };
            match parent {
                None => return Ok(Some(chain)),
                Some(p) => {
                    if chain.len() > CATEGORY_DEPTH_MAX {
                        return Ok(Some(chain));
                    }
                    chain.push(p);
                    current = p;
                }
            }
        }
    }

    /// Levels below `id` (0 for a folder with no subfolders).
    async fn folder_height(
        conn: &mut sqlx::SqliteConnection,
        case_id: Uuid,
        id: Uuid,
    ) -> Result<usize> {
        let mut level = vec![id];
        let mut height = 0;
        while height <= CATEGORY_DEPTH_MAX {
            let mut next = Vec::new();
            for parent in &level {
                let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
                    "SELECT id FROM bookmark_categories WHERE case_id = ? AND parent_id = ?",
                )
                .bind(case_id)
                .bind(parent)
                .fetch_all(&mut *conn)
                .await
                .context("Failed to read a bookmark folder's subfolders")?;
                for (child,) in rows {
                    next.push(Uuid::from_slice(&child).context("Invalid folder id")?);
                }
            }
            if next.is_empty() {
                break;
            }
            height += 1;
            level = next;
        }
        Ok(height)
    }

    /// Create a folder, optionally under `parent`.
    pub async fn create_bookmark_folder(
        &self,
        case_id: Uuid,
        name: &str,
        color: Option<&str>,
        parent: Option<Uuid>,
    ) -> Result<std::result::Result<Uuid, FolderRefusal>> {
        // The checks and the write share one IMMEDIATE transaction: with the
        // write lock taken first, a concurrent move cannot change the tree
        // between the check and the write. Refusal returns drop (roll back).
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .context("Failed to begin the bookmark folder transaction")?;
        if let Some(parent) = parent {
            let Some(chain) = Self::folder_chain(&mut tx, case_id, parent).await? else {
                return Ok(Err(FolderRefusal::ParentNotInCase));
            };
            if chain.len() + 1 > CATEGORY_DEPTH_MAX {
                return Ok(Err(FolderRefusal::TooDeep));
            }
        }
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO bookmark_categories (id, case_id, name, color, created_at, parent_id)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(case_id)
        .bind(name)
        .bind(color.unwrap_or("#ffc107"))
        .bind(Utc::now().timestamp())
        .bind(parent)
        .execute(&mut *tx)
        .await
        .context("Failed to create bookmark category")?;
        tx.commit()
            .await
            .context("Failed to commit the bookmark category")?;
        debug!("Created bookmark folder '{}' for case {}", name, case_id);
        Ok(Ok(id))
    }

    /// Move a folder under `new_parent`, or to the top level with `None`.
    pub async fn move_bookmark_folder(
        &self,
        case_id: Uuid,
        id: Uuid,
        new_parent: Option<Uuid>,
    ) -> Result<std::result::Result<(), FolderRefusal>> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .context("Failed to begin the bookmark folder transaction")?;
        if Self::folder_parent(&mut tx, case_id, id).await?.is_none() {
            return Ok(Err(FolderRefusal::NotFound));
        }
        if let Some(parent) = new_parent {
            let Some(chain) = Self::folder_chain(&mut tx, case_id, parent).await? else {
                return Ok(Err(FolderRefusal::ParentNotInCase));
            };
            // The new parent's own ancestry includes the folder: a cycle.
            if chain.contains(&id) {
                return Ok(Err(FolderRefusal::Cycle));
            }
            let height = Self::folder_height(&mut tx, case_id, id).await?;
            if chain.len() + 1 + height > CATEGORY_DEPTH_MAX {
                return Ok(Err(FolderRefusal::TooDeep));
            }
        }
        sqlx::query("UPDATE bookmark_categories SET parent_id = ? WHERE id = ? AND case_id = ?")
            .bind(new_parent)
            .bind(id)
            .bind(case_id)
            .execute(&mut *tx)
            .await
            .context("Failed to move a bookmark folder")?;
        tx.commit()
            .await
            .context("Failed to commit the bookmark folder move")?;
        Ok(Ok(()))
    }
}
