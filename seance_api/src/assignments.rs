//! Examiner assignment and personal bookmarks over HTTP (ROADMAP §3.15).
//!
//! Every route here is case-scoped, so `case_access_middleware` has already
//! refused a caller with no grant on the case, and refused a `read_only`
//! caller any non-GET request, before a handler runs.
//!
//! * **Assignment** — only a case `owner` (or an admin) may assign or
//!   withdraw. The assignee must be able to record reviews in the case
//!   (`read_write` or `owner`, or an admin): a `read_only` examiner cannot
//!   file a review, so assigning review work to one would be a record of work
//!   that could never be done. Progress and the queue are derived from the
//!   review ledger and count only the assignee's OWN reviews.
//! * **Personal bookmarks** — private scratch marks. Every read and write is
//!   scoped to the caller's own user row; nobody, the owner and admins
//!   included, can list another examiner's marks through this API. They never
//!   reach a report; promoting one into the shared set is audited.

use axum::{
    extract::{Path, Query as AxumQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use tracing::info;
use uuid::Uuid;

use crate::auth::{AuthenticatedRole, AuthenticatedUser};
use crate::{audit_required, require_case_owner_or_admin, ApiError, AppState};

fn internal(what: &str) -> impl FnOnce(anyhow::Error) -> ApiError + '_ {
    move |e| ApiError::InternalServerError(format!("{what}: {e}"))
}

/// The caller's own user row id. Personal state needs a real account: the
/// env-bootstrap admin and the auth-disabled `local` identity have no row and
/// are told so rather than sharing one anonymous scratch space.
async fn caller_user_id(state: &AppState, username: &str) -> Result<Uuid, ApiError> {
    state
        .db
        .get_user_by_username(username)
        .await
        .map_err(internal("Failed to resolve user"))?
        .map(|u| u.id)
        .ok_or_else(|| {
            ApiError::Forbidden(
                "This needs a user account: the signed-in identity has no user row \
                 (the bootstrap admin or auth-disabled mode)"
                    .to_string(),
            )
        })
}

/// Whether an assignment has missed its due date. Derived at read time from
/// the review ledger, never stored: finished work is not overdue, and a
/// withdrawn assignment is nobody's backlog.
pub fn is_overdue(
    due_at: Option<i64>,
    now: i64,
    total: i64,
    reviewed_by_assignee: i64,
    withdrawn: bool,
) -> bool {
    match due_at {
        Some(due) => !withdrawn && due < now && reviewed_by_assignee < total,
        None => false,
    }
}

/// A due date must lie ahead: one already past would be born overdue and say
/// nothing the owner meant.
fn validate_due(due_at: Option<i64>) -> Result<(), ApiError> {
    match due_at {
        Some(due) if due <= chrono::Utc::now().timestamp() => Err(ApiError::InvalidRequest(
            "The due date is in the past; nothing was recorded.".to_string(),
        )),
        _ => Ok(()),
    }
}

fn assignment_json(
    a: &seance_db::CaseAssignment,
    p: &seance_db::AssignmentProgress,
) -> serde_json::Value {
    serde_json::json!({
        "id": a.id,
        "case_id": a.case_id,
        "assignee_user_id": a.assignee_user_id,
        "assignee_username": a.assignee_username,
        "assigned_by": a.assigned_by,
        "note": a.note,
        "created_at": a.created_at,
        "withdrawn_at": a.withdrawn_at,
        "withdrawn_by": a.withdrawn_by,
        "due_at": a.due_at,
        "reassigned_from": a.reassigned_from,
        "overdue": is_overdue(
            a.due_at,
            chrono::Utc::now().timestamp(),
            p.total,
            p.reviewed_by_assignee,
            a.withdrawn_at.is_some(),
        ),
        // Two overlapping counts, never summed: every reviewed item is also an
        // opened one. Both are the ASSIGNEE's own ledger rows only.
        "progress": {
            "total": p.total,
            "opened_by_assignee": p.opened_by_assignee,
            "reviewed_by_assignee": p.reviewed_by_assignee,
            "counts": "the assignee's own openings and reviews; a colleague's review of an assigned item is not counted",
        },
    })
}

#[derive(Debug, Deserialize)]
pub struct CreateAssignmentRequest {
    pub assignee_user_id: Uuid,
    pub artifact_ids: Vec<Uuid>,
    pub note: Option<String>,
    /// Unix seconds; must lie in the future.
    #[serde(default)]
    pub due_at: Option<i64>,
}

/// The assignee, checked: they exist, are active, and can record reviews in
/// this case. Shared by creating and reassigning, so one rule governs both.
async fn require_assignable(
    state: &AppState,
    case_id: Uuid,
    assignee_user_id: Uuid,
) -> Result<seance_db::UserRow, ApiError> {
    let assignee = state
        .db
        .get_user_by_id(assignee_user_id)
        .await
        .map_err(internal("Failed to look up the assignee"))?
        .ok_or_else(|| {
            ApiError::InvalidRequest(format!(
                "User {} does not exist; nothing was recorded.",
                assignee_user_id
            ))
        })?;
    if !assignee.active {
        return Err(ApiError::InvalidRequest(format!(
            "{} is deactivated and cannot be assigned work; nothing was recorded.",
            assignee.username
        )));
    }
    if assignee.role != "admin" {
        let level = state
            .db
            .case_access_level(assignee.id, case_id)
            .await
            .map_err(internal("Failed to check the assignee's case access"))?;
        match level.as_deref() {
            Some("read_write") | Some("owner") => {}
            Some("read_only") => {
                return Err(ApiError::InvalidRequest(format!(
                    "{} holds read_only access to this case and cannot record reviews, \
                     so review work cannot be assigned to them. Grant read_write first; \
                     nothing was recorded.",
                    assignee.username
                )))
            }
            _ => {
                return Err(ApiError::InvalidRequest(format!(
                    "{} has no access to this case. Grant read_write first; nothing was \
                     recorded.",
                    assignee.username
                )))
            }
        }
    }
    Ok(assignee)
}

/// POST /api/v1/cases/:case_id/assignments — owner or admin only.
pub async fn create_assignment(
    State(state): State<AppState>,
    Path(case_id): Path<Uuid>,
    Extension(user): Extension<AuthenticatedUser>,
    Extension(role): Extension<AuthenticatedRole>,
    Json(payload): Json<CreateAssignmentRequest>,
) -> Result<Response, ApiError> {
    info!(
        "POST /api/v1/cases/{}/assignments ({} artifact(s))",
        case_id,
        payload.artifact_ids.len()
    );
    let acting_id = require_case_owner_or_admin(&state, &user.0, &role.0, case_id).await?;

    validate_due(payload.due_at)?;
    let assignee = require_assignable(&state, case_id, payload.assignee_user_id).await?;

    let note = payload.note.as_deref().filter(|n| !n.trim().is_empty());
    let created = state
        .db
        .create_assignment(
            case_id,
            assignee.id,
            acting_id,
            note,
            payload.due_at,
            &payload.artifact_ids,
        )
        .await
        .map_err(internal("Failed to record the assignment"))?;
    let assignment_id = match created {
        Ok(id) => id,
        Err(seance_db::AssignmentRefusal::Empty) => {
            return Err(ApiError::InvalidRequest(
                "An assignment must name at least one artifact; nothing was recorded.".into(),
            ))
        }
        Err(seance_db::AssignmentRefusal::OverCap(n)) => {
            // Refused, never truncated: a truncated assignment would tell the
            // owner the examiner had been given work that was never recorded.
            return Err(ApiError::InvalidRequest(format!(
                "An assignment may name at most {} artifacts; this one named {}. Split it — \
                 the request was refused in full and nothing was recorded.",
                seance_db::ASSIGNMENT_ITEMS_MAX,
                n
            )));
        }
        Err(seance_db::AssignmentRefusal::NotInCase(ids)) => {
            return Err(ApiError::InvalidRequest(format!(
                "{} artifact id(s) are not in this case ({}); the request was refused in \
                 full and nothing was recorded.",
                ids.len(),
                ids.iter()
                    .take(10)
                    .map(Uuid::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    };

    let a = state
        .db
        .get_assignment(case_id, assignment_id)
        .await
        .map_err(internal("Failed to read the assignment back"))?
        .ok_or_else(|| ApiError::InternalServerError("Assignment vanished".into()))?;
    let progress = state
        .db
        .assignment_progress(assignment_id)
        .await
        .map_err(internal("Failed to read assignment progress"))?;

    audit_required(
        &state,
        Some(case_id),
        &user.0,
        "assignment_created",
        Some("assignment"),
        Some(assignment_id),
        Some(&format!(
            "assignee: {}, artifacts: {}",
            a.assignee_username, a.item_count
        )),
    )
    .await?;

    Ok((StatusCode::CREATED, Json(assignment_json(&a, &progress))).into_response())
}

#[derive(Debug, Deserialize)]
pub struct ListAssignmentsQuery {
    /// `true` restricts the listing to assignments whose assignee is the
    /// caller.
    #[serde(default)]
    pub mine: bool,
}

/// GET /api/v1/cases/:case_id/assignments — anyone with access to the case.
pub async fn list_assignments(
    State(state): State<AppState>,
    Path(case_id): Path<Uuid>,
    Extension(user): Extension<AuthenticatedUser>,
    AxumQuery(query): AxumQuery<ListAssignmentsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut all = state
        .db
        .list_assignments(case_id)
        .await
        .map_err(internal("Failed to list assignments"))?;
    if query.mine {
        let me = caller_user_id(&state, &user.0).await?;
        all.retain(|a| a.assignee_user_id == me);
    }
    let mut out = Vec::with_capacity(all.len());
    for a in &all {
        let p = state
            .db
            .assignment_progress(a.id)
            .await
            .map_err(internal("Failed to read assignment progress"))?;
        out.push(assignment_json(a, &p));
    }
    Ok(Json(serde_json::json!({ "assignments": out })))
}

#[derive(Debug, Deserialize)]
pub struct QueueQuery {
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: usize,
}

/// GET /api/v1/cases/:case_id/assignments/:assignment_id/queue — the items
/// the assignee has not yet reviewed, paged.
pub async fn assignment_queue(
    State(state): State<AppState>,
    Path((case_id, assignment_id)): Path<(Uuid, Uuid)>,
    AxumQuery(query): AxumQuery<QueueQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let a = state
        .db
        .get_assignment(case_id, assignment_id)
        .await
        .map_err(internal("Failed to read the assignment"))?
        .ok_or_else(|| {
            ApiError::ResourceNotFound(format!("No assignment {assignment_id} in this case"))
        })?;
    let page = state
        .db
        .assignment_queue(assignment_id, query.limit, query.offset)
        .await
        .map_err(internal("Failed to read the assignment queue"))?;
    let progress = state
        .db
        .assignment_progress(assignment_id)
        .await
        .map_err(internal("Failed to read assignment progress"))?;
    Ok(Json(serde_json::json!({
        "assignment": assignment_json(&a, &progress),
        "progress": assignment_json(&a, &progress)["progress"],
        "items": page.items,
        "limit": page.limit,
        "offset": page.offset,
        "has_more": page.has_more,
        "undecodable": page.undecodable,
    })))
}

/// POST /api/v1/cases/:case_id/assignments/:assignment_id/withdraw — owner or
/// admin. The assignment is kept, marked withdrawn.
pub async fn withdraw_assignment(
    State(state): State<AppState>,
    Path((case_id, assignment_id)): Path<(Uuid, Uuid)>,
    Extension(user): Extension<AuthenticatedUser>,
    Extension(role): Extension<AuthenticatedRole>,
) -> Result<Response, ApiError> {
    let acting_id = require_case_owner_or_admin(&state, &user.0, &role.0, case_id).await?;
    let Some(existing) = state
        .db
        .get_assignment(case_id, assignment_id)
        .await
        .map_err(internal("Failed to read the assignment"))?
    else {
        return Err(ApiError::ResourceNotFound(format!(
            "No assignment {assignment_id} in this case"
        )));
    };
    let changed = state
        .db
        .withdraw_assignment(case_id, assignment_id, acting_id)
        .await
        .map_err(internal("Failed to withdraw the assignment"))?;
    if !changed {
        return Ok((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": {
                    "code": "ALREADY_WITHDRAWN",
                    "message": format!(
                        "Assignment {} was already withdrawn at {}",
                        assignment_id,
                        existing.withdrawn_at.unwrap_or_default()
                    ),
                }
            })),
        )
            .into_response());
    }
    audit_required(
        &state,
        Some(case_id),
        &user.0,
        "assignment_withdrawn",
        Some("assignment"),
        Some(assignment_id),
        Some(&format!("assignee: {}", existing.assignee_username)),
    )
    .await?;
    let a = state
        .db
        .get_assignment(case_id, assignment_id)
        .await
        .map_err(internal("Failed to read the assignment back"))?
        .ok_or_else(|| ApiError::InternalServerError("Assignment vanished".into()))?;
    let p = state
        .db
        .assignment_progress(assignment_id)
        .await
        .map_err(internal("Failed to read assignment progress"))?;
    Ok(Json(assignment_json(&a, &p)).into_response())
}

#[derive(Debug, Deserialize)]
pub struct ReassignRequest {
    pub assignee_user_id: Uuid,
    pub note: Option<String>,
    #[serde(default)]
    pub due_at: Option<i64>,
}

/// POST /api/v1/cases/:case_id/assignments/:assignment_id/reassign — owner or
/// admin. The assignment is withdrawn (kept, marked) and a new one over the
/// same items goes to the new examiner, subject to the same assignee rules as
/// a fresh assignment.
pub async fn reassign_assignment(
    State(state): State<AppState>,
    Path((case_id, assignment_id)): Path<(Uuid, Uuid)>,
    Extension(user): Extension<AuthenticatedUser>,
    Extension(role): Extension<AuthenticatedRole>,
    Json(payload): Json<ReassignRequest>,
) -> Result<Response, ApiError> {
    let acting_id = require_case_owner_or_admin(&state, &user.0, &role.0, case_id).await?;
    validate_due(payload.due_at)?;
    let assignee = require_assignable(&state, case_id, payload.assignee_user_id).await?;
    let note = payload.note.as_deref().filter(|n| !n.trim().is_empty());
    let outcome = state
        .db
        .reassign_assignment(
            case_id,
            assignment_id,
            assignee.id,
            acting_id,
            note,
            payload.due_at,
        )
        .await
        .map_err(internal("Failed to reassign the assignment"))?;
    let new_id = match outcome {
        Ok(id) => id,
        Err(seance_db::ReassignRefusal::NotFound) => {
            return Err(ApiError::ResourceNotFound(format!(
                "No assignment {assignment_id} in this case"
            )))
        }
        Err(seance_db::ReassignRefusal::AlreadyWithdrawn) => {
            return Ok((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": {
                        "code": "ALREADY_WITHDRAWN",
                        "message": format!(
                            "Assignment {assignment_id} was already withdrawn; nothing was \
                             reassigned."
                        ),
                    }
                })),
            )
                .into_response())
        }
    };
    let a = state
        .db
        .get_assignment(case_id, new_id)
        .await
        .map_err(internal("Failed to read the assignment back"))?
        .ok_or_else(|| ApiError::InternalServerError("Assignment vanished".into()))?;
    let progress = state
        .db
        .assignment_progress(new_id)
        .await
        .map_err(internal("Failed to read assignment progress"))?;
    audit_required(
        &state,
        Some(case_id),
        &user.0,
        "assignment_reassigned",
        Some("assignment"),
        Some(new_id),
        Some(&format!(
            "assignee: {}, from assignment: {}, artifacts: {}",
            a.assignee_username, assignment_id, a.item_count
        )),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(assignment_json(&a, &progress))).into_response())
}

// --- Personal bookmarks ---

#[derive(Debug, Deserialize)]
pub struct PersonalBookmarkRequest {
    pub artifact_id: Uuid,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PersonalListQuery {
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: usize,
}

/// GET /api/v1/cases/:case_id/personal_bookmarks — the caller's own.
pub async fn list_personal_bookmarks(
    State(state): State<AppState>,
    Path(case_id): Path<Uuid>,
    Extension(user): Extension<AuthenticatedUser>,
    AxumQuery(query): AxumQuery<PersonalListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let me = caller_user_id(&state, &user.0).await?;
    let page = state
        .db
        .list_personal_bookmarks(case_id, me, query.limit, query.offset)
        .await
        .map_err(internal("Failed to list personal bookmarks"))?;
    Ok(Json(serde_json::json!({
        "items": page.items,
        "limit": page.limit,
        "offset": page.offset,
        "has_more": page.has_more,
        "undecodable": page.undecodable,
        "visibility": "private to you; never included in a report until promoted to the shared bookmarks",
    })))
}

/// POST /api/v1/cases/:case_id/personal_bookmarks — create or update the
/// caller's own mark. Not audited: a private scratch mark is not an act on the
/// case record. Promotion is.
pub async fn upsert_personal_bookmark(
    State(state): State<AppState>,
    Path(case_id): Path<Uuid>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(payload): Json<PersonalBookmarkRequest>,
) -> Result<Response, ApiError> {
    let me = caller_user_id(&state, &user.0).await?;
    let id = state
        .db
        .upsert_personal_bookmark(case_id, payload.artifact_id, me, payload.note.as_deref())
        .await
        .map_err(internal("Failed to write the personal bookmark"))?
        .ok_or_else(|| {
            ApiError::InvalidRequest(format!(
                "Artifact {} is not in this case; nothing was recorded.",
                payload.artifact_id
            ))
        })?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": id, "artifact_id": payload.artifact_id })),
    )
        .into_response())
}

/// DELETE /api/v1/cases/:case_id/personal_bookmarks/:id — the caller's own.
pub async fn delete_personal_bookmark(
    State(state): State<AppState>,
    Path((case_id, id)): Path<(Uuid, Uuid)>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<StatusCode, ApiError> {
    let me = caller_user_id(&state, &user.0).await?;
    if state
        .db
        .delete_personal_bookmark(case_id, me, id)
        .await
        .map_err(internal("Failed to delete the personal bookmark"))?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::ResourceNotFound(format!(
            "You have no personal bookmark {id} in this case"
        )))
    }
}

/// POST /api/v1/cases/:case_id/personal_bookmarks/:id/promote — move one of
/// the caller's marks into the shared set (which the report reads). Audited.
pub async fn promote_personal_bookmark(
    State(state): State<AppState>,
    Path((case_id, id)): Path<(Uuid, Uuid)>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Response, ApiError> {
    let me = caller_user_id(&state, &user.0).await?;
    let outcome = state
        .db
        .promote_personal_bookmark(case_id, me, id, &user.0)
        .await
        .map_err(internal("Failed to promote the personal bookmark"))?;
    match outcome {
        seance_db::PromotionOutcome::Promoted(shared) => {
            audit_required(
                &state,
                Some(case_id),
                &user.0,
                "personal_bookmark_promoted",
                Some("personal_bookmark"),
                Some(id),
                Some(&format!("shared bookmark: {shared}")),
            )
            .await?;
            Ok(Json(serde_json::json!({
                "promoted": true,
                "shared_bookmark_id": shared,
            }))
            .into_response())
        }
        seance_db::PromotionOutcome::NotFound => Err(ApiError::ResourceNotFound(format!(
            "You have no personal bookmark {id} in this case"
        ))),
        seance_db::PromotionOutcome::AlreadyPromoted(shared) => Ok((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": {
                    "code": "ALREADY_PROMOTED",
                    "message": format!("Already promoted to shared bookmark {shared}"),
                },
                "shared_bookmark_id": shared,
            })),
        )
            .into_response()),
        seance_db::PromotionOutcome::SharedBookmarkExists(shared) => Ok((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": {
                    "code": "SHARED_BOOKMARK_EXISTS",
                    "message": "This artifact already has a shared bookmark. Promotion was \
                                refused rather than overwrite its note; edit the shared \
                                bookmark instead.",
                },
                "shared_bookmark_id": shared,
            })),
        )
            .into_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::is_overdue;

    #[test]
    fn overdue_is_derived_never_stored() {
        // No due date is never overdue.
        assert!(!is_overdue(None, 1_000, 4, 0, false));
        // Past due with items left: overdue.
        assert!(is_overdue(Some(500), 1_000, 4, 3, false));
        // Past due but every item reviewed: finished, not overdue.
        assert!(!is_overdue(Some(500), 1_000, 4, 4, false));
        // Not yet due.
        assert!(!is_overdue(Some(2_000), 1_000, 4, 0, false));
        // A withdrawn assignment is nobody's backlog.
        assert!(!is_overdue(Some(500), 1_000, 4, 0, true));
    }
}
