import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { IngestModal } from './IngestModal'

/**
 * The sidebar's ingest entry point.
 *
 * The open flag is scoped to the case. This button lives in `CaseLayout`'s
 * sidebar, outside the routed content, so it stays mounted when `:caseId`
 * changes — browser back/forward between two cases does exactly that with the
 * dialog on screen. An unscoped flag leaves the modal open across that change
 * holding the file selection, evidence type and PROFILE chosen for the previous
 * case (profiles are per-case ids), while "Start ingest" posts to
 * `ingestSource(caseId, …)` with the live one. The examiner then attaches an
 * exhibit to a case they were not looking at when they picked it, under an
 * ingest profile that belongs to a different case — a chain-of-custody error
 * made by the UI rather than by them.
 *
 * Closing it drops the selection with it, which is the intended outcome:
 * evidence must be chosen against the case it is being attached to.
 */
export function IngestButton({ caseId }: { caseId: string }) {
  const [open, setOpen] = useEntityScopedState(caseId, false)
  return (
    <div style={{ padding: '10px 12px 0' }}>
      <button
        className="btn btn-primary"
        style={{ width: '100%' }}
        onClick={() => setOpen(true)}
      >
        Ingest Evidence
      </button>
      {open && <IngestModal caseId={caseId} onClose={() => setOpen(false)} />}
    </div>
  )
}
