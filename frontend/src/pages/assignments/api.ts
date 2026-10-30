import { apiFetch } from "../../api/http";

/**
 * Examiner assignment and personal bookmarks (ROADMAP §3.15).
 *
 * Progress counts only the ASSIGNEE's own ledger rows: a colleague's review of
 * an assigned item is not the assignee's work. `opened_by_assignee` and
 * `reviewed_by_assignee` overlap (every reviewed item was also opened) and are
 * never added together.
 */
export interface AssignmentProgress {
  total: number;
  opened_by_assignee: number;
  reviewed_by_assignee: number;
  counts: string;
}

export interface Assignment {
  id: string;
  case_id: string;
  assignee_user_id: string;
  assignee_username: string;
  assigned_by: string | null;
  note: string | null;
  created_at: number;
  withdrawn_at: number | null;
  withdrawn_by: string | null;
  /** The owner's target, Unix seconds; null = none set. */
  due_at: number | null;
  /** The assignment this one replaced, when it came from a reassignment. */
  reassigned_from: string | null;
  /** Derived by the server from the review ledger, never stored: past due with
   *  items the assignee has not reviewed, and not withdrawn. */
  overdue: boolean;
  progress: AssignmentProgress;
}

export interface QueueItem {
  artifact_id: string;
  artifact_type: string;
  /** When the assignee first opened it; null = not yet opened by them. */
  opened_at: number | null;
}

export interface AssignmentQueue {
  assignment: Assignment;
  progress: AssignmentProgress;
  items: QueueItem[];
  limit: number;
  offset: number;
  has_more: boolean;
  undecodable: number;
}

export const listAssignments = (caseId: string, mine = false) =>
  apiFetch<{ assignments: Assignment[] }>(`/cases/${caseId}/assignments`, {
    query: mine ? { mine: "true" } : undefined,
  });

export const getAssignmentQueue = (
  caseId: string,
  assignmentId: string,
  offset = 0,
) =>
  apiFetch<AssignmentQueue>(
    `/cases/${caseId}/assignments/${assignmentId}/queue`,
    { query: { offset: String(offset) } },
  );

export const createAssignment = (
  caseId: string,
  body: {
    assignee_user_id: string;
    artifact_ids: string[];
    note?: string;
    due_at?: number;
  },
) =>
  apiFetch<Assignment>(`/cases/${caseId}/assignments`, {
    method: "POST",
    body,
  });

export const withdrawAssignment = (caseId: string, assignmentId: string) =>
  apiFetch<Assignment>(
    `/cases/${caseId}/assignments/${assignmentId}/withdraw`,
    { method: "POST" },
  );

/** Withdraw an assignment and give the same items to another examiner. The
 *  old assignment is kept, marked withdrawn. */
export const reassignAssignment = (
  caseId: string,
  assignmentId: string,
  body: { assignee_user_id: string; note?: string; due_at?: number },
) =>
  apiFetch<Assignment>(
    `/cases/${caseId}/assignments/${assignmentId}/reassign`,
    { method: "POST", body },
  );

/** A private scratch mark: seen only by its owner, never reported. */
export interface PersonalBookmark {
  id: string;
  case_id: string;
  artifact_id: string;
  owner_user_id: string;
  note: string | null;
  created_at: number;
  updated_at: number;
  promoted_at: number | null;
  promoted_bookmark_id: string | null;
  /** True only while the shared bookmark it was promoted to still exists —
   *  exactly when the report carries it. `promoted_at` alone does not mean
   *  "in the report": that bookmark may have been deleted since. */
  in_shared_set: boolean;
  artifact_type: string;
}

export interface PersonalBookmarkPage {
  items: PersonalBookmark[];
  limit: number;
  offset: number;
  has_more: boolean;
  undecodable: number;
  visibility: string;
}

export const listPersonalBookmarks = (caseId: string) =>
  apiFetch<PersonalBookmarkPage>(`/cases/${caseId}/personal_bookmarks`);

export const addPersonalBookmark = (
  caseId: string,
  artifactId: string,
  note?: string,
) =>
  apiFetch<{ id: string }>(`/cases/${caseId}/personal_bookmarks`, {
    method: "POST",
    body: { artifact_id: artifactId, note },
  });

export const deletePersonalBookmark = (caseId: string, id: string) =>
  apiFetch<void>(`/cases/${caseId}/personal_bookmarks/${id}`, {
    method: "DELETE",
  });

export const promotePersonalBookmark = (caseId: string, id: string) =>
  apiFetch<{ promoted: boolean; shared_bookmark_id: string }>(
    `/cases/${caseId}/personal_bookmarks/${id}/promote`,
    { method: "POST" },
  );
