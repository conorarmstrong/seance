import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Modal } from './Modal'
import { humanizeType } from '../pages/analysis/lib'
import { formatCount } from '../lib/format'
import { getPivot, listPinnedPivots, pinPivot, unpinPivot } from '../pages/pivot/api'
import './pivot.css'

/**
 * Pin this answer to the case, so it reaches the report instead of being
 * re-derived by hand while writing it (ROADMAP §5.13).
 *
 * Pinning stores the answer **as it is now**, with the examiner and the
 * moment. The report renders that snapshot and separately re-runs the same
 * value, so a case that has grown since shows both figures rather than quietly
 * reporting a different one — which is why the control says "as it stands"
 * rather than implying a live link.
 */
function PinControl({ caseId, value }: { caseId: string; value: string }) {
  const queryClient = useQueryClient()
  const [note, setNote] = useState('')
  const pinned = useQuery({
    queryKey: ['pinned-pivots', caseId],
    queryFn: () => listPinnedPivots(caseId),
    enabled: caseId !== '',
  })
  const already = pinned.data?.pivots.find((p) => p.value === value) ?? null

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ['pinned-pivots', caseId] })
  const pin = useMutation({
    mutationFn: () => pinPivot(caseId, value, note.trim() || undefined),
    onSuccess: invalidate,
  })
  const unpin = useMutation({
    mutationFn: (id: string) => unpinPivot(caseId, id),
    onSuccess: invalidate,
  })

  // A failed pin must not read as a pin: the examiner would write the report
  // expecting the section to be there.
  const error = pin.error ?? unpin.error

  if (already) {
    return (
      <div className="pivot-pin" data-testid="pivot-pinned">
        <p className="pivot-pin-state">
          Pinned to the case by <strong>{already.examiner}</strong>. The report
          carries this answer as it was when pinned, and re-checks the value at
          the time the report is produced.
        </p>
        <div className="pivot-pin-row">
          <button
            type="button"
            className="pivot-pin-btn"
            disabled={pin.isPending}
            onClick={() => pin.mutate()}
          >
            {pin.isPending ? 'Re-pinning…' : 'Re-pin with the current answer'}
          </button>
          <button
            type="button"
            className="pivot-pin-btn pivot-pin-remove"
            disabled={unpin.isPending}
            onClick={() => unpin.mutate(already.id)}
          >
            {unpin.isPending ? 'Removing…' : 'Remove from the case'}
          </button>
        </div>
        {error && (
          <p className="pivot-error" role="alert">
            That did not go through: {(error as Error).message}. The pin is
            unchanged.
          </p>
        )}
      </div>
    )
  }

  return (
    <div className="pivot-pin" data-testid="pivot-pin">
      <div className="pivot-pin-row">
        <input
          className="pivot-pin-note"
          type="text"
          value={note}
          placeholder="Why this value matters (optional)"
          aria-label="Why this value matters"
          onChange={(e) => setNote(e.target.value)}
        />
        <button
          type="button"
          className="pivot-pin-btn"
          disabled={pin.isPending}
          onClick={() => pin.mutate()}
        >
          {pin.isPending ? 'Pinning…' : 'Pin this answer to the case'}
        </button>
      </div>
      <p className="pivot-pin-hint">
        Pinning records this answer <em>as it stands</em>, with your name and the
        time, and puts it in the report under &ldquo;Values Traced Across the
        Evidence&rdquo;. The report also re-checks the value when it is
        produced, so if the case has grown both figures are shown.
      </p>
      {error && (
        <p className="pivot-error" role="alert">
          That did not go through: {(error as Error).message}. Nothing was
          pinned.
        </p>
      )}
    </div>
  )
}

/**
 * The universal pivot: given one value — an IP, a hash, an account, a filename
 * — show every artifact in the case that references it, grouped by the kind of
 * record each is. This is the move an examiner makes constantly, and the
 * grouping ("6 network flows, 2 DNS resolutions, 1 registry hive") is what
 * turns a flat hit list into a picture of the value's role in the case.
 */
export function PivotDrawer({
  caseId,
  value,
  onClose,
}: {
  caseId: string
  value: string
  onClose: () => void
}) {
  const query = useQuery({
    queryKey: ['pivot', caseId, value],
    queryFn: () => getPivot(caseId, value),
  })
  const data = query.data

  return (
    <Modal title={`Everything touching ${value}`} onClose={onClose}>
      <div className="pivot">
        <div className="pivot-head">
          <code className="pivot-value">{value}</code>
          {data && (
            <span className="pivot-total mono">
              {formatCount(data.total_matches)} artifact
              {data.total_matches === 1 ? '' : 's'}
              {data.truncated
                ? ` · showing the first ${formatCount(data.grouped)}`
                : ''}
            </span>
          )}
        </div>

        {query.isPending ? (
          <p className="pivot-status">Finding every artifact that references it…</p>
        ) : query.isError ? (
          <p className="pivot-status pivot-error">
            Pivot failed: {(query.error as Error).message}
          </p>
        ) : !data || data.groups.length === 0 ? (
          <p className="pivot-status">
            No artifact in this case references <code>{value}</code>. That is a
            finding in itself — the value is not present in what has been parsed.
          </p>
        ) : (
          <div className="pivot-groups">
            {data.groups.map((g) => (
              <section className="pivot-group" key={g.kind}>
                <header className="pivot-group-head">
                  <h3>{humanizeType(g.kind)}</h3>
                  <span className="pivot-group-n mono">{formatCount(g.count)}</span>
                </header>
                <ul className="pivot-samples">
                  {g.samples.map((s) => (
                    <li key={s.artifact_id}>
                      <Link
                        className="pivot-sample"
                        to={`/cases/${caseId}/artifacts/${s.artifact_id}`}
                        onClick={onClose}
                      >
                        <span className="pivot-sample-name">{s.name}</span>
                        {s.snippet && (
                          <span className="pivot-sample-snippet">{s.snippet}</span>
                        )}
                      </Link>
                    </li>
                  ))}
                  {g.count > g.samples.length && (
                    <li className="pivot-more">
                      <Link
                        to={`/cases/${caseId}/search?q=${encodeURIComponent(value)}`}
                        onClick={onClose}
                      >
                        + {formatCount(g.count - g.samples.length)} more — open in
                        search
                      </Link>
                    </li>
                  )}
                </ul>
              </section>
            ))}
          </div>
        )}

        {/* Offered whether or not the value matched anything: "this address
            appears nowhere in the evidence" is an answer worth carrying into
            the report, and it is the one an examiner is most likely to be
            asked to stand behind. Withheld only while the pivot has not
            answered, since there would be nothing to pin. */}
        {data && <PinControl caseId={caseId} value={value} />}
      </div>
    </Modal>
  )
}
