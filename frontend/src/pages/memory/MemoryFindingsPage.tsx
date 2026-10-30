import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import { getMemoryTampering, type StageEnvelope } from './api'
import { useMemoryContext } from './memoryContext'
import { LensGate } from './LensState'
import { FindingCard, SEVERITY_ORDER, severityOf } from './FindingCard'
import { readTamperingSignals } from './normalize'
import { formatCount } from '../../lib/format'

/**
 * The findings lens: every tampering signal this capture produced.
 *
 * This lens has the most dangerous empty state in the section. "No tampering
 * signals" and "the tampering scan did not run" would both be an empty list,
 * and the first is an exculpatory finding an examiner might put in a report. So
 * the two never render alike, and the empty state says explicitly what it does
 * and does not cover.
 *
 * The severity filter is a URL parameter, so a filtered list is a shareable
 * citation rather than a private view.
 */
export function MemoryFindingsPage() {
  const { caseId, imageId, scopeKey } = useMemoryContext()
  const [params, setParams] = useSearchParams()
  const severity = params.get('severity')

  const query = useEntityScopedQuery<StageEnvelope>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'tampering'],
    queryFn: () => getMemoryTampering(caseId, imageId),
    retry: false,
  })

  // The signals are two levels inside the scan record (one record per capture,
  // processes inside it, signals inside each process), which the list-shaped
  // row reader could not reach: it found no matching row key and fell back to
  // the whole record as a single row, so this lens rendered one "Signal with no
  // title" card on every capture and never showed a real signal.
  const { rows, unreadable } = useMemo(
    () => readTamperingSignals(query.scoped),
    [query.scoped],
  )

  const severities = useMemo(() => {
    const seen = new Set<string>()
    for (const row of rows) seen.add(severityOf(row))
    return [...seen].sort(
      (a, b) => (SEVERITY_ORDER[a] ?? 9) - (SEVERITY_ORDER[b] ?? 9),
    )
  }, [rows])

  const visible = useMemo(() => {
    const filtered =
      severity == null ? rows : rows.filter((row) => severityOf(row) === severity)
    return [...filtered].sort(
      (a, b) =>
        (SEVERITY_ORDER[severityOf(a)] ?? 9) -
        (SEVERITY_ORDER[severityOf(b)] ?? 9),
    )
  }, [rows, severity])

  const setSeverity = (next: string | null) => {
    const updated = new URLSearchParams(params)
    if (next == null) updated.delete('severity')
    else updated.set('severity', next)
    setParams(updated)
  }

  return (
    <div className="mem-findings">
      <div className="page-actions">
        <button
          type="button"
          className={severity == null ? 'btn btn-primary' : 'btn'}
          onClick={() => setSeverity(null)}
        >
          All
        </button>
        {severities.map((level) => (
          <button
            key={level}
            type="button"
            className={severity === level ? 'btn btn-primary' : 'btn'}
            onClick={() => setSeverity(level)}
          >
            {level}
          </button>
        ))}
      </div>

      {unreadable > 0 && (
        <div className="error-note" role="note" data-testid="mem-tamper-unreadable">
          <strong>
            {formatCount(unreadable)} tampering record
            {unreadable === 1 ? '' : 's'} could not be read.
          </strong>{' '}
          The analysis sent a shape this client does not recognise, so any signal
          those records carry is missing from the list below. Nothing here is a
          finding that the processes they cover were untampered with.
        </div>
      )}

      <LensGate
        label="Tampering signals"
        pending={query.isPending}
        stale={query.stale}
        error={query.isError ? query.error : undefined}
        envelope={query.scoped}
        rowCount={rows.length}
        columns={4}
        emptyTitle={
          unreadable > 0
            ? 'No tampering signal could be read'
            : 'No tampering signal was recorded'
        }
        emptyReason={
          unreadable > 0 ? (
            <>
              Every tampering record this capture produced was in a shape this
              client could not read. Nothing here is a statement about what the
              scan found, and the empty list is not an exculpatory finding.
            </>
          ) : (
            <>
              The tampering scan ran and recorded nothing. That is a statement
              about the checks it performs — image hollowing, process ghosting
              and executable memory with no file behind it — and about nothing
              else. A technique it does not cover leaves no trace here.
            </>
          )
        }
      >
        {visible.length === 0 ? (
          <div className="empty-state">
            <h3>No signal at this severity</h3>
            <p>
              {formatCount(rows.length)} signal
              {rows.length === 1 ? '' : 's'} exist at other severities. Clear the
              filter to see them.
            </p>
          </div>
        ) : (
          <div className="mem-finding-list">
            {visible.map((row) => (
              <FindingCard
                key={row.key}
                row={row}
                caseId={caseId}
                imageId={imageId}
              />
            ))}
          </div>
        )}
      </LensGate>
    </div>
  )
}
