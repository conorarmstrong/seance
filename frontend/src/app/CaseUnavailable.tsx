import { Link } from 'react-router-dom'
import { ApiRequestError } from '../api/http'

/**
 * What to tell the examiner when the case shell cannot load its case.
 *
 * Only a 404 is evidence the case is gone. Every other failure — the server
 * busy behind a running ingest, a timeout, a network drop — says nothing about
 * whether the case exists, and this shell used to render all of them as "it
 * may have been deleted" (HUNT-078). A statement on screen that the evidence
 * may be gone, made on the strength of a slow request, is the kind of claim
 * this product must not make.
 */
export function caseUnavailableCopy(error: unknown): {
  title: string
  body: string
  deleted: boolean
} {
  if (error instanceof ApiRequestError && error.status === 404) {
    return {
      title: 'Case not found',
      body: 'This case does not exist here. It may have been deleted, or the workspace was reset since it was opened.',
      deleted: true,
    }
  }
  const detail = error instanceof Error && error.message ? error.message : 'no response'
  return {
    title: 'Case could not be loaded',
    body: `The server did not answer for this case (${detail}). Nothing here shows the case is gone: the server may be busy — a running ingest holds the database's writer — or unreachable. Retry, or open it again from the case list.`,
    deleted: false,
  }
}

export function CaseUnavailable({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const copy = caseUnavailableCopy(error)
  return (
    <div className="case-missing">
      <h1>{copy.title}</h1>
      <p>{copy.body}</p>
      <div className="case-missing-actions">
        {!copy.deleted && (
          <button type="button" className="btn btn-primary" onClick={onRetry}>
            Retry
          </button>
        )}
        <Link className={copy.deleted ? 'btn btn-primary' : 'btn'} to="/">
          Back to all cases
        </Link>
      </div>
    </div>
  )
}
