import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { X } from 'lucide-react'
import { formatCount, formatUtc } from '../../lib/format'
import { humanizeType } from '../analysis/lib'
import { listPinnedPivots, unpinPivot } from '../pivot/api'

/**
 * Values the examiner traced across the evidence and pinned to the case
 * (ROADMAP §5.13).
 *
 * It sits on the Bookmarks page because that is where examiner-authored marks
 * live, and a pinned pivot is one: the tool answered the question, the examiner
 * decided the answer belonged in the document. It is deliberately **not** on
 * the Findings page, which carries Séance's own claims.
 *
 * Two things are stated rather than implied, because a reader of this panel is
 * about to rely on what the report will say:
 *
 * * **The counts are a snapshot.** They are what the pivot answered when the
 *   value was pinned. The report re-checks the value when it is produced and
 *   shows both figures where they differ, so a case that has grown since does
 *   not silently change the document.
 * * **A capped answer is a sample.** The per-kind counts of a capped pivot do
 *   not add up to its total, and a sample presented as a total is the defect
 *   class this project treats as HIGH.
 */
export function TracedValuesPanel({ caseId }: { caseId: string }) {
  const queryClient = useQueryClient()
  const query = useQuery({
    queryKey: ['pinned-pivots', caseId],
    queryFn: () => listPinnedPivots(caseId),
    enabled: caseId !== '',
  })
  const unpin = useMutation({
    mutationFn: (id: string) => unpinPivot(caseId, id),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ['pinned-pivots', caseId] }),
  })

  if (query.isPending) return null
  // A failed load must not render as "nothing is pinned": an examiner would
  // write the report expecting no such section.
  if (query.isError) {
    return (
      <div className="error-note" role="note" data-testid="tv-error">
        Traced values unavailable: {(query.error as Error).message}. Nothing
        here says none are pinned to this case.
      </div>
    )
  }
  const pivots = query.data?.pivots ?? []
  if (pivots.length === 0) return null

  return (
    <section className="tv" data-testid="traced-values">
      <h2 className="tv-heading">Values traced across the evidence</h2>
      <p className="tv-sub">
        {formatCount(pivots.length)}{' '}
        {pivots.length === 1 ? 'value' : 'values'} pinned to this case. Each is
        the answer a pivot gave <em>at the moment it was pinned</em>; the report
        renders that answer and re-checks the value when it is produced, so a
        case that has grown since shows both figures.
      </p>
      <ul className="tv-list">
        {pivots.map((p) => (
          <li key={p.id} className="tv-item" data-testid="tv-item">
            <div className="tv-item-head">
              <code className="tv-value">{p.value}</code>
              <span className="tv-count mono">
                {formatCount(p.total_matches)} artifact
                {p.total_matches === 1 ? '' : 's'}
              </span>
              <button
                type="button"
                className="tv-remove icon-btn"
                aria-label={`Remove ${p.value} from the case`}
                disabled={unpin.isPending}
                onClick={() => unpin.mutate(p.id)}
              >
                <X size={13} />
              </button>
            </div>
            {p.note && <p className="tv-note">{p.note}</p>}
            <p className="tv-meta">
              Pinned by <strong>{p.examiner}</strong> on{' '}
              {formatUtc(new Date(p.pinned_at * 1000).toISOString())}
            </p>
            {p.truncated && (
              <p className="warn-note" role="note" data-testid="tv-truncated">
                More artifacts referenced this value than the pivot groups at
                once, so the per-kind counts below are a sample: they do not add
                up to the total above and must not be read as the whole.
              </p>
            )}
            <div className="tv-groups">
              {p.groups.map((g) => (
                <span className="tv-group" key={g.kind}>
                  {humanizeType(g.kind)}{' '}
                  <span className="mono">{formatCount(g.count)}</span>
                </span>
              ))}
            </div>
            <Link
              className="tv-open"
              to={`/cases/${caseId}/search?q=${encodeURIComponent(p.value)}`}
            >
              Open the full hit list in search
            </Link>
          </li>
        ))}
      </ul>
      {unpin.error && (
        <p className="error-note" role="alert">
          That did not go through: {(unpin.error as Error).message}. Nothing was
          removed.
        </p>
      )}
    </section>
  )
}
