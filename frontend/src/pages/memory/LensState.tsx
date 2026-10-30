import type { ReactNode } from 'react'
import { SkeletonTable } from '../../components/Skeleton'
import { envelopeStatus, terminated } from './normalize'
import type { StageEnvelope } from './api'

/**
 * The states every memory lens must implement, in one place.
 *
 * The distinction this component exists to enforce: **a stage that did not run
 * never renders like a stage that found nothing**. An empty table under a
 * crashed scanner reads as "the machine was clean", which is the most dangerous
 * thing this UI could say. So a failed stage is an error note, a capped stage
 * shows its rows *and* says they are a floor, a search that stopped before it
 * had seen everything says it is undetermined, and a genuinely empty result
 * says why it might be empty rather than shrugging.
 *
 * Pending is a table-shaped skeleton, never a spinner over a blank page, so the
 * examiner can tell "loading" from "nothing here" at a glance.
 *
 * `rowCount` is required rather than optional, and that is deliberate. A stage
 * that ran and found nothing still emits a record, so the envelope alone says
 * `complete` and the children would render a headers-only table with no
 * explanation — the honest empty copy below would never appear. Making the
 * count mandatory means a lens cannot be written that silently shows a blank
 * table where a sentence is owed.
 */
export function LensGate({
  /** What the lens is called, used in the loading and error copy. */
  label,
  pending,
  /** True when the data in hand belongs to a previous case or capture. */
  stale,
  error,
  envelope,
  /** How many rows this lens decoded from the envelope. */
  rowCount,
  emptyTitle,
  emptyReason,
  children,
  columns = 6,
}: {
  label: string
  pending: boolean
  stale?: boolean
  error?: unknown
  envelope: StageEnvelope | null | undefined
  rowCount: number
  emptyTitle: string
  emptyReason: ReactNode
  children: ReactNode
  columns?: number
}) {
  if (pending || stale) {
    return <SkeletonTable rows={10} cols={columns} label={`Loading ${label}`} />
  }

  if (error != null) {
    const message =
      error instanceof Error ? error.message : 'the server did not say why'
    return (
      <div className="error-note" role="note">
        <strong>{label} could not be loaded.</strong> This is a load error, not
        an empty result — nothing below is a statement about what the capture
        contains. ({message})
      </div>
    )
  }

  const status = envelopeStatus(envelope, rowCount)

  if (status.kind === 'not_run') {
    return (
      <div className="error-note" role="note">
        <strong>{label}: this analysis did not run.</strong> {terminated(status.message)} An
        empty list is not evidence of absence here, so none is shown.
      </div>
    )
  }

  if (status.kind === 'undetermined') {
    return (
      <div className="warn-note" role="note">
        <strong>{label}: not determined.</strong> {terminated(status.message)} Neither
        &ldquo;there is none&rdquo; nor &ldquo;the stage did not run&rdquo; is
        true here, so neither is shown.
      </div>
    )
  }

  // Capped *and* nothing decodable came back. Neither the empty copy below
  // ("the scan ran and recovered nothing") nor a bare table is true here: the
  // stage stopped early, so nothing follows from the absence of rows.
  if (rowCount === 0 && status.kind === 'partial') {
    return (
      <div className="warn-note" role="note">
        <strong>{label}: nothing was returned, and the result is a floor.</strong>{' '}
        {terminated(status.message)} No row is shown, and this is not a finding that there
        is none.
      </div>
    )
  }

  if (status.kind === 'empty' || rowCount === 0) {
    return (
      <div className="empty-state">
        <h3>{emptyTitle}</h3>
        <p>{emptyReason}</p>
      </div>
    )
  }

  return (
    <>
      {status.kind === 'partial' && (
        <div className="warn-note mem-floor" role="note">
          <strong>These counts are a floor, not a total.</strong>{' '}
          {terminated(status.message)} More may exist in the capture than is listed here.
        </div>
      )}
      {children}
    </>
  )
}
