import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { formatCount } from "../../lib/format";
import { humanizeType } from "../analysis/lib";
import {
  deletePersonalBookmark,
  listPersonalBookmarks,
  promotePersonalBookmark,
} from "./api";

/**
 * The "Mine" root of the bookmark tree (ROADMAP §3.15; owner decision
 * 2026-09-26). A personal bookmark is a private scratch mark: only its author
 * sees it and it never reaches a report. The report states how many exist and
 * were left out. Adding one to the shared bookmarks — the "Shared" root, which
 * is what the report prints — is an explicit, audited step.
 */
export function PersonalBookmarksPanel({ caseId }: { caseId: string }) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["personal-bookmarks", caseId],
    queryFn: () => listPersonalBookmarks(caseId),
    enabled: caseId !== "",
  });
  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["personal-bookmarks", caseId] });
    queryClient.invalidateQueries({ queryKey: ["bookmarks", caseId] });
  };
  const promote = useMutation({
    mutationFn: (id: string) => promotePersonalBookmark(caseId, id),
    onSuccess: invalidate,
  });
  const remove = useMutation({
    mutationFn: (id: string) => deletePersonalBookmark(caseId, id),
    onSuccess: invalidate,
  });

  return (
    <section className="pb" data-testid="personal-bookmarks">
      <h2 className="pb-heading">Mine (personal)</h2>
      <p className="muted">
        Only you see these. They are never included in a report; the report
        states only how many exist. Add one to the shared bookmarks to report it
        — that step is recorded in the audit log.
      </p>
      {query.isPending && <p className="muted">Reading your marks…</p>}
      {query.isError && (
        <div className="error-note" role="note" data-testid="pb-error">
          Your personal bookmarks could not be read:{" "}
          {(query.error as Error).message}. This does not mean you have none.
        </div>
      )}
      {query.data && query.data.items.length === 0 && (
        <p className="muted" data-testid="pb-empty">
          You have no personal bookmarks in this case.
        </p>
      )}
      {query.data && query.data.items.length > 0 && (
        <ul className="pb-list">
          {query.data.items.map((b) => (
            <li key={b.id} data-testid="pb-item">
              <Link to={`/cases/${caseId}/artifacts/${b.artifact_id}`}>
                {humanizeType(b.artifact_type)}{" "}
                <span className="mono">{b.artifact_id.slice(0, 8)}</span>
              </Link>
              {b.note && <span className="pb-note"> — {b.note}</span>}{" "}
              {b.in_shared_set ? (
                <span className="badge" data-testid="pb-in-shared">
                  in shared bookmarks
                </span>
              ) : (
                <>
                  {b.promoted_at !== null && (
                    // Promoted once, but the shared bookmark it became was
                    // deleted since: the report no longer carries it and
                    // counts it among the excluded personal marks.
                    <span className="muted" data-testid="pb-promotion-gone">
                      (the shared bookmark it became was deleted; it is not in
                      the report){" "}
                    </span>
                  )}
                  <button
                    type="button"
                    className="btn btn-sm"
                    disabled={promote.isPending}
                    onClick={() => promote.mutate(b.id)}
                  >
                    Add to shared bookmarks
                  </button>
                </>
              )}{" "}
              <button
                type="button"
                className="btn btn-sm"
                disabled={remove.isPending}
                onClick={() => remove.mutate(b.id)}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      {query.data?.has_more && (
        <p className="warn-note" role="note">
          More personal bookmarks exist than this list shows.
        </p>
      )}
      {query.data && query.data.undecodable > 0 && (
        <p className="warn-note" role="note">
          {formatCount(query.data.undecodable)} could not be read and are
          missing from this list.
        </p>
      )}
      {promote.isSuccess && (
        <p className="muted" data-testid="pb-promoted-note">
          Added to the shared bookmarks; it will appear in the report.
        </p>
      )}
      {promote.error && (
        <p className="error-note" role="alert">
          Not added: {(promote.error as Error).message}. If the artifact already
          has a shared bookmark, edit that one instead.
        </p>
      )}
      {remove.error && (
        <p className="error-note" role="alert">
          Not removed: {(remove.error as Error).message}.
        </p>
      )}
    </section>
  );
}
