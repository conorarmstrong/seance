import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiRequestError } from "../../api/http";
import { formatCount, formatUtc } from "../../lib/format";
import { listCaseAccess } from "../search/api";
import {
  listAssignments,
  reassignAssignment,
  withdrawAssignment,
  type Assignment,
} from "./api";

/**
 * Every assignment in the case, for the owner (ROADMAP §3.15): progress,
 * the due date, whether it is overdue, and the two things an owner does with
 * an active one — withdraw it, or give the same items to another examiner.
 *
 * Offered only when the access list answers, because that list and the
 * assignment endpoints share one owner-or-admin check on the server: a control
 * shown on the strength of a 200 here cannot drift from what the server will
 * accept.
 *
 * Neither action deletes anything. A withdrawn assignment stays on the record
 * and is shown as withdrawn: "was this examiner ever asked to look at these?"
 * is a question the case may have to answer.
 */
export function AssignmentsOverview({ caseId }: { caseId: string }) {
  const access = useQuery({
    queryKey: ["case-access", caseId],
    queryFn: () => listCaseAccess(caseId),
    enabled: caseId !== "",
  });
  const list = useQuery({
    queryKey: ["assignments", caseId],
    queryFn: () => listAssignments(caseId),
    enabled: caseId !== "" && access.isSuccess,
  });

  if (!access.data) return null;
  if (list.isPending) {
    return (
      <section className="ao" data-testid="ao-loading">
        <h2>Assignments</h2>
        <p className="muted">Reading the case&apos;s assignments…</p>
      </section>
    );
  }
  if (list.isError) {
    return (
      <section className="ao">
        <h2>Assignments</h2>
        <div className="error-note" role="note">
          The assignments could not be read: {(list.error as Error).message}.
          This does not mean none were made.
        </div>
      </section>
    );
  }
  const rows = list.data?.assignments ?? [];
  const eligible = access.data.filter(
    (g) => g.access_level === "read_write" || g.access_level === "owner",
  );
  return (
    <section className="ao" data-testid="assignments-overview">
      <h2>Assignments</h2>
      {rows.length === 0 ? (
        <p className="muted">No work has been assigned in this case.</p>
      ) : (
        rows.map((a) => (
          <OverviewRow
            key={a.id}
            caseId={caseId}
            assignment={a}
            eligible={eligible.filter((g) => g.user_id !== a.assignee_user_id)}
          />
        ))
      )}
    </section>
  );
}

function OverviewRow({
  caseId,
  assignment: a,
  eligible,
}: {
  caseId: string;
  assignment: Assignment;
  eligible: { user_id: string; username: string; access_level: string }[];
}) {
  const queryClient = useQueryClient();
  const [target, setTarget] = useState("");
  const settled = () =>
    queryClient.invalidateQueries({ queryKey: ["assignments", caseId] });
  const reassign = useMutation({
    mutationFn: () =>
      reassignAssignment(caseId, a.id, { assignee_user_id: target }),
    onSuccess: settled,
  });
  const withdraw = useMutation({
    mutationFn: () => withdrawAssignment(caseId, a.id),
    onSuccess: settled,
  });
  const active = a.withdrawn_at === null;
  const p = a.progress;
  const error = reassign.error ?? withdraw.error;
  return (
    <div className="ao-row" data-testid="ao-row">
      <p>
        <strong>{a.assignee_username}</strong>
        {a.note ? <> — {a.note}</> : null}
        {!active && <span className="muted"> · withdrawn</span>}
        {a.reassigned_from && (
          <span className="muted"> · reassigned from an earlier assignment</span>
        )}
      </p>
      <p>
        {formatCount(p.reviewed_by_assignee)} reviewed of {formatCount(p.total)}{" "}
        <span className="muted">(their own reviews only)</span>
        {a.due_at !== null && (
          <>
            {" "}
            · due {formatUtc(new Date(a.due_at * 1000).toISOString())}
          </>
        )}
        {a.overdue && (
          <>
            {" "}
            <strong className="error-note">Overdue</strong>
          </>
        )}
      </p>
      {active && (
        <p>
          <label>
            Reassign to{" "}
            <select
              aria-label="Reassign to"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            >
              <option value="">— choose an examiner —</option>
              {eligible.map((g) => (
                <option key={g.user_id} value={g.user_id}>
                  {g.username} ({g.access_level})
                </option>
              ))}
            </select>
          </label>{" "}
          <button
            type="button"
            className="btn"
            disabled={target === "" || reassign.isPending}
            onClick={() => reassign.mutate()}
          >
            Reassign
          </button>{" "}
          <button
            type="button"
            className="btn"
            disabled={withdraw.isPending}
            onClick={() => withdraw.mutate()}
          >
            Withdraw
          </button>
        </p>
      )}
      {(reassign.isSuccess || withdraw.isSuccess) && (
        <p className="muted" data-testid="ao-done">
          Done. The earlier assignment is kept on the record, marked withdrawn.
        </p>
      )}
      {error && (
        <p className="error-note" role="alert">
          {wasRefused(error) ? (
            <>Not changed: {error.message}. Nothing was recorded.</>
          ) : (
            <>
              The server did not confirm the change: {(error as Error).message}.
              It may have been recorded — read the list again before retrying.
            </>
          )}
        </p>
      )}
    </div>
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
