import { useMutation, useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { formatCount } from '../../lib/format'
import {
  backfillCaseSearchIndex,
  listCaseAccess,
  reindexCaseSearch,
} from './api'
import { useSearchRepairProgress } from './repairProgress'

/**
 * The search-index display-name repair, at the point where its results are
 * read.
 *
 * Two separate things live here, and they are shown to different people on
 * purpose. The CONTROL is offered only to an examiner the server would let run
 * a repair, because a button that answers 403 is worse than no button. The
 * STATUS is shown to everyone on the case: a repair rewrites the names in the
 * table below it, and a colleague reading those names while they are being
 * rewritten needs to know that as much as the person who started it does.
 *
 * Nothing here says a repair makes the case searchable. It cannot: it walks
 * what is already indexed. That limit is in the paragraph beside the button
 * rather than in a tooltip, because it is the sentence most likely to keep
 * "reindexed" out of a report as a claim about coverage.
 */
export function SearchIndexRepair({ caseId }: { caseId: string }) {
  const progress = useSearchRepairProgress(caseId)

  // Asked of the server rather than inferred from the session; see
  // `listCaseAccess` for why that is the only sound way to ask. Not retried:
  // the refusal is the answer, and a client that keeps asking would only make
  // the same 403 three times.
  const access = useQuery({
    queryKey: ['case-access', caseId],
    queryFn: () => listCaseAccess(caseId),
    enabled: caseId !== '',
    retry: false,
    staleTime: 5 * 60_000,
  })

  const repair = useMutation({
    mutationFn: () => reindexCaseSearch(caseId),
  })

  // The other half (LIVE-028): what the case has and the index does not.
  const backfill = useMutation({
    mutationFn: () => backfillCaseSearchIndex(caseId),
  })

  // The pass reports its last batch with `done` equal to `total`, and reports
  // nothing at all when it fails. So this marks the point where the pass
  // stopped walking documents — never that it succeeded, which only the audit
  // log knows.
  const passEnded =
    progress != null && progress.total != null && progress.done >= progress.total

  // The two passes count different things: the repair walks documents already
  // in the index, the backfill walks the case's artifacts. Saying "documents"
  // for both would put a number beside a noun it is not a count of.
  const unit = progress?.kind === 'backfill' ? 'artifacts' : 'documents'
  const walked =
    progress == null
      ? ''
      : progress.total == null
        ? `${formatCount(progress.done)} ${unit} so far`
        : `${formatCount(progress.done)} of ${formatCount(progress.total)} ${unit}`

  return (
    <>
      {access.isSuccess && (
        <details className="srch-repair">
          <summary>Search index maintenance</summary>
          <div className="srch-repair-body">
            <p>
              Repairing recomputes the display name of every document this case
              already has in its search index, from the metadata stored beside
              it. It does not add artifacts that were never indexed — an ingest
              that missed evidence leaves a short index and it is still short
              afterwards — so a repair cannot make this case&rsquo;s search
              coverage complete. Backfilling, below, is what adds them.
            </p>
            <button
              type="button"
              className="btn"
              // Disabled only while this request is in the air. Whether a
              // repair is already running is the server's question to answer,
              // and it answers it plainly; a button greyed out on this page's
              // reading of the event stream would be greyed out for a repair
              // that had already died.
              disabled={repair.isPending}
              onClick={() => repair.mutate()}
            >
              {repair.isPending ? 'Starting…' : 'Repair display names'}
            </button>
            {repair.data != null && (
              <p className="srch-repair-receipt" role="status">
                Repair{' '}
                <span className="mono">{repair.data.repair_id}</span> started. It
                runs on the server, and this page is never told how it ends: the
                outcome is written to this case&rsquo;s{' '}
                <Link to={`/cases/${caseId}/audit`}>audit log</Link> as{' '}
                <span className="mono">search_index_repair_completed</span>,
                carrying the renamed, total and undecodable document counts, or{' '}
                <span className="mono">search_index_repair_failed</span>.
              </p>
            )}
            <p>
              Backfilling is the operation that <em>does</em> add them. It walks
              this case&rsquo;s artifacts in the database, finds the ones with
              no document in the search index, and indexes those. What it adds
              carries <strong>metadata only</strong>: an artifact read back from
              the database has no bytes behind it, so the text extracted from a
              file at ingest is not reconstructed. A backfilled file is findable
              by name, path and metadata; a keyword inside it is not found until
              the evidence is re-ingested.
            </p>
            <button
              type="button"
              className="btn"
              disabled={backfill.isPending}
              onClick={() => backfill.mutate()}
            >
              {backfill.isPending ? 'Starting…' : 'Backfill missing documents'}
            </button>
            {backfill.data != null && (
              <p className="srch-repair-receipt" role="status">
                Backfill{' '}
                <span className="mono">{backfill.data.backfill_id}</span> started
                over {formatCount(backfill.data.artifacts)} artifacts. It runs on
                the server, and this page is never told how it ends: the outcome
                is written to this case&rsquo;s{' '}
                <Link to={`/cases/${caseId}/audit`}>audit log</Link> as{' '}
                <span className="mono">search_index_backfill_completed</span>,
                carrying the examined, already-indexed, added and failed counts,
                or <span className="mono">search_index_backfill_failed</span>.{' '}
                {backfill.data.note}
              </p>
            )}
            {backfill.isError && (
              <div className="error-note" role="alert">
                {/* The server's words again, and for the same reason: the
                    refusal names the override that rescues a case whose server
                    died mid-pass. */}
                Backfill request failed: {backfill.error.message} Nothing on
                this page changed; the case&rsquo;s audit log is the record of
                whether a backfill was started.
              </div>
            )}
            {repair.isError && (
              <div className="error-note" role="alert">
                {/* The server's own words, kept intact: when it refuses a second
                    repair it names the override that rescues a case whose server
                    died mid-pass, and replacing that with a friendlier sentence
                    would take the escape hatch away from the only person who
                    needs it. The claim about what changed is deliberately about
                    this page and not about the server, because a reply that
                    never arrived is indistinguishable here from one that was
                    never sent. */}
                Repair request failed: {repair.error.message} Nothing on this
                page changed; the case&rsquo;s audit log is the record of
                whether a repair was started.
              </div>
            )}
          </div>
        </details>
      )}

      {progress != null && passEnded && (
        <div className="warn-note srch-repair-status" role="status">
          A search-index {progress.kind === 'backfill' ? 'backfill' : 'repair'}{' '}
          has processed all {formatCount(progress.total)} {unit} in this
          case&rsquo;s {progress.kind === 'backfill' ? 'case' : 'index'}. Run
          the search again to see the result. Whether the pass finished or
          stopped part-way, and what it changed, is recorded in this
          case&rsquo;s <Link to={`/cases/${caseId}/audit`}>audit log</Link> —
          this page is not told.
        </div>
      )}
      {progress != null && !passEnded && progress.kind === 'backfill' && (
        <div className="warn-note srch-repair-status" role="status">
          A search-index backfill is running over this case: {walked}. Documents
          are being added while you read, so a search may return more than it
          did a moment ago. What it adds carries metadata only, not the text
          extracted from file bytes at ingest.
        </div>
      )}
      {progress != null && !passEnded && progress.kind === 'repair' && (
        <div className="warn-note srch-repair-status" role="status">
          A search-index repair is running over this case: {walked}. Display
          names in these results may change while it runs. It is repairing names
          only; it adds nothing that was never indexed.
        </div>
      )}
      {progress == null && backfill.data != null && (
        <div className="warn-note srch-repair-status" role="status">
          A search-index backfill has been started for this case. Documents may
          be added to these results while it runs.
        </div>
      )}
      {progress == null && repair.data != null && (
        <div className="warn-note srch-repair-status" role="status">
          A search-index repair has been started for this case. Display names in
          these results may change while it runs.
        </div>
      )}
    </>
  )
}
