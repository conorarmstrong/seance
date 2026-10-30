import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiRequestError } from "../../api/http";
import { formatCount } from "../../lib/format";
import { listCaseAccess } from "../search/api";
import { createAssignment } from "./api";
import { endOfLocalDay } from "./due";

/**
 * Assign a set of artifacts to a named examiner (ROADMAP §3.15).
 *
 * Offered only when the case's access list answers, because that list and the
 * assignment endpoint are gated by the same owner-or-admin check on the
 * server: a control shown on the strength of a 200 here cannot drift from what
 * the assignment will accept.
 *
 * Only examiners who can record reviews (read_write or owner) are offered. A
 * read_only examiner cannot file a review, so assigning review work to one
 * would record work that could never be done; the server refuses it too.
 */
export function AssignPanel({
  caseId,
  artifactIds,
}: {
  caseId: string;
  artifactIds: string[];
}) {
  const queryClient = useQueryClient();
  const access = useQuery({
    queryKey: ["case-access", caseId],
    queryFn: () => listCaseAccess(caseId),
    enabled: caseId !== "",
  });
  const [assignee, setAssignee] = useState("");
  const [due, setDue] = useState("");
  const assign = useMutation({
    mutationFn: () =>
      createAssignment(caseId, {
        assignee_user_id: assignee,
        artifact_ids: artifactIds,
        // Omitted, not null, when no date was chosen: the server reads absence
        // as "no due date".
        ...(due === "" ? {} : { due_at: endOfLocalDay(due) }),
      }),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["assignments", caseId] }),
  });

  // Not the owner (or the question failed): no control is offered.
  if (!access.data) return null;
  const eligible = access.data.filter(
    (g) => g.access_level === "read_write" || g.access_level === "owner",
  );
  const readOnly = access.data.filter((g) => g.access_level === "read_only");
  const n = artifactIds.length;

  return (
    <section className="assign" data-testid="assign-panel">
      <label>
        Assign to{" "}
        <select
          aria-label="Assign to"
          value={assignee}
          onChange={(e) => setAssignee(e.target.value)}
        >
          <option value="">— choose an examiner —</option>
          {eligible.map((g) => (
            <option key={g.user_id} value={g.user_id}>
              {g.username} ({g.access_level})
            </option>
          ))}
        </select>
      </label>{" "}
      <label>
        Due{" "}
        <input
          type="date"
          aria-label="Due"
          value={due}
          onChange={(e) => setDue(e.target.value)}
        />
      </label>{" "}
      <button
        type="button"
        className="btn"
        disabled={assignee === "" || n === 0 || assign.isPending}
        onClick={() => assign.mutate()}
      >
        Assign {formatCount(n)} listed {n === 1 ? "artifact" : "artifacts"}
      </button>
      {readOnly.length > 0 && (
        <p className="muted">
          Not offered (read_only access cannot record reviews):{" "}
          {readOnly.map((g) => g.username).join(", ")}.
        </p>
      )}
      {assign.isSuccess && (
        <p className="muted" data-testid="assign-done">
          Assigned. Their progress counts only their own reviews.
        </p>
      )}
      {assign.error && (
        <p className="error-note" role="alert">
          {wasRefused(assign.error) ? (
            <>Not assigned: {assign.error.message}. Nothing was recorded.</>
          ) : (
            // The server writes the assignment before its audit entry, so a
            // failure after the write reaches here with the assignment stored.
            <>
              The server did not confirm the assignment:{" "}
              {(assign.error as Error).message}. It may have been recorded —
              check the examiner&apos;s queue before assigning again.
            </>
          )}
        </p>
      )}
    </section>
  );
}

/** A 4xx answer is a refusal checked before anything is written; anything
 *  else (5xx, network) may have failed after the write. */
function wasRefused(error: unknown): error is ApiRequestError {
  return (
    error instanceof ApiRequestError &&
    error.status >= 400 &&
    error.status < 500
  );
}
