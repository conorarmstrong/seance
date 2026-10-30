import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { formatCount, formatUtc } from "../../lib/format";
import { humanizeType } from "../analysis/lib";
import { getAssignmentQueue, listAssignments, type Assignment } from "./api";

/**
 * "My queue" (ROADMAP §3.15): the work a case owner assigned to the signed-in
 * examiner, and what of it is left.
 *
 * Three states are kept apart, as the review-ledger panel keeps them: still
 * reading, could not be read, and genuinely nothing assigned. A failed fetch
 * rendered as "nothing assigned" would tell an examiner they had no work.
 *
 * Progress is the examiner's OWN reviews. A colleague's review of an assigned
 * item does not clear it from this queue, and the caption says so.
 */
export function AssignmentQueue({ caseId }: { caseId: string }) {
  const query = useQuery({
    queryKey: ["assignments", caseId, "mine"],
    queryFn: () => listAssignments(caseId, true),
    enabled: caseId !== "",
  });

  if (query.isPending) {
    return (
      <section className="aq" data-testid="aq-loading">
        <h2 className="aq-heading">My queue</h2>
        <p className="muted">Reading your assignments…</p>
      </section>
    );
  }
  if (query.isError) {
    return (
      <section className="aq">
        <h2 className="aq-heading">My queue</h2>
        <div className="error-note" role="note" data-testid="aq-error">
          Your assignments could not be read: {(query.error as Error).message}.
          This does not mean nothing is assigned to you.
        </div>
      </section>
    );
  }

  const all = query.data?.assignments ?? [];
  const active = all.filter((a) => a.withdrawn_at === null);
  const withdrawn = all.length - active.length;

  return (
    <section className="aq" data-testid="assignment-queue">
      <h2 className="aq-heading">My queue</h2>
      {active.length === 0 ? (
        <p className="muted" data-testid="aq-empty">
          Nothing assigned to you in this case.
        </p>
      ) : (
        active.map((a) => (
          <AssignmentBlock key={a.id} caseId={caseId} assignment={a} />
        ))
      )}
      {withdrawn > 0 && (
        <p className="muted" data-testid="aq-withdrawn">
          {formatCount(withdrawn)} withdrawn{" "}
          {withdrawn === 1 ? "assignment is" : "assignments are"} kept on the
          record and not shown as work.
        </p>
      )}
    </section>
  );
}

function AssignmentBlock({
  caseId,
  assignment,
}: {
  caseId: string;
  assignment: Assignment;
}) {
  const queue = useQuery({
    queryKey: ["assignments", caseId, assignment.id, "queue"],
    queryFn: () => getAssignmentQueue(caseId, assignment.id),
  });
  const p = assignment.progress;
  return (
    <div className="aq-block" data-testid="aq-block">
      {assignment.note && <p className="aq-note">{assignment.note}</p>}
      <p className="aq-progress" data-testid="aq-progress">
        <strong>
          {formatCount(p.reviewed_by_assignee)} reviewed of{" "}
          {formatCount(p.total)}
        </strong>{" "}
        ({formatCount(p.opened_by_assignee)} opened). These count your own
        reviews only: a colleague&apos;s review of an item does not clear it
        from your queue. Assigned{" "}
        {formatUtc(new Date(assignment.created_at * 1000).toISOString())}.
        {assignment.due_at !== null && (
          <>
            {" "}
            Due{" "}
            <span data-testid="aq-due">
              {formatUtc(new Date(assignment.due_at * 1000).toISOString())}
            </span>
            .
          </>
        )}
        {assignment.overdue && (
          <>
            {" "}
            <strong className="error-note" data-testid="aq-overdue">
              Overdue
            </strong>
          </>
        )}
      </p>
      {queue.isPending && <p className="muted">Reading the queue…</p>}
      {queue.isError && (
        <div className="error-note" role="note" data-testid="aq-queue-error">
          The remaining items could not be read:{" "}
          {(queue.error as Error).message}.
        </div>
      )}
      {queue.data && queue.data.items.length === 0 && !queue.data.has_more && (
        <EmptyQueueStatement
          total={queue.data.progress.total}
          undecodable={queue.data.undecodable}
        />
      )}
      {queue.data && queue.data.items.length > 0 && (
        <ul className="aq-list">
          {queue.data.items.map((item) => (
            <li key={item.artifact_id} data-testid="aq-item">
              <Link to={`/cases/${caseId}/artifacts/${item.artifact_id}`}>
                {humanizeType(item.artifact_type)}{" "}
                <span className="mono">{item.artifact_id.slice(0, 8)}</span>
              </Link>{" "}
              <span className="muted">
                {item.opened_at === null ? "not yet opened" : "opened"}
              </span>
            </li>
          ))}
        </ul>
      )}
      {queue.data?.has_more && (
        <p className="warn-note" role="note">
          More items remain than this list shows; they are still assigned to
          you.
        </p>
      )}
      {queue.data && queue.data.undecodable > 0 && (
        <p className="warn-note" role="note">
          {formatCount(queue.data.undecodable)} assigned item(s) could not be
          read and are missing from this list.
        </p>
      )}
    </div>
  );
}

/**
 * What an empty queue page means. "You have reviewed every item" is claimed
 * only when the assignment still holds items and every one of them could be
 * read: an unreadable item is not a reviewed one, and an assignment whose
 * artifacts were all deleted from the case was not reviewed at all.
 */
function EmptyQueueStatement({
  total,
  undecodable,
}: {
  total: number;
  undecodable: number;
}) {
  if (undecodable > 0) {
    return (
      <p className="warn-note" role="note" data-testid="aq-unreadable-only">
        No readable item remains in this queue, but {formatCount(undecodable)}{" "}
        assigned item(s) could not be read. Whether you have reviewed them
        cannot be told from here.
      </p>
    );
  }
  if (total === 0) {
    return (
      <p className="muted" data-testid="aq-no-items">
        This assignment no longer holds any item: the artifacts assigned in it
        are no longer in the case. Nothing here was reviewed by you as part of
        it.
      </p>
    );
  }
  return (
    <p className="muted" data-testid="aq-done">
      You have reviewed every item in this assignment.
    </p>
  );
}
