import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Pager } from '../../components/Pager'
import { truncateHash } from '../../lib/format'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { getHashHits } from './api'

const PAGE_SIZE = 50

export function HitsPanel({
  caseId,
  hashSetId,
  title,
  onClose,
}: {
  caseId: string
  /** null lists hits across all hash sets. */
  hashSetId: string | null
  title: string
  onClose: () => void
}) {
  // The panel is not remounted when the examiner opens a different hash set, so
  // a plain `useState` page number carries across: open set A, page to 5, open
  // set B with two pages, and B's own hits render as "No hits" while they sit
  // on page 1 (B4-028). Scoping the page to the set resolves during render, so
  // the wrong page is never queried at all.
  const [page, setPage] = useEntityScopedState(
    `${caseId}/${hashSetId ?? 'all'}`,
    1,
  )

  const hitsQuery = useQuery({
    queryKey: ['hash-hits', caseId, hashSetId, page],
    queryFn: () =>
      getHashHits(caseId, {
        hash_set_id: hashSetId ?? undefined,
        page,
        page_size: PAGE_SIZE,
      }),
  })

  const data = hitsQuery.data
  const totalPages = data ? Math.max(Math.ceil(data.total / data.page_size), 1) : 1

  return (
    <div className="panel hs-hits-panel">
      <div className="hs-hits-head">
        <h2 className="panel-title">{title}</h2>
        <button className="btn" onClick={onClose}>
          Close
        </button>
      </div>

      {hitsQuery.isPending && <div className="loading">Loading hits…</div>}
      {hitsQuery.isError && (
        <div className="error-note">{hitsQuery.error.message}</div>
      )}
      {data && data.hits.length === 0 && (
        <div className="empty-state">
          <h3>No hits</h3>
          <p>No matches recorded in this case.</p>
        </div>
      )}
      {data && data.hits.length > 0 && (
        <>
          <table className="data-table">
            <thead>
              <tr>
                <th>Artifact</th>
                <th>Path</th>
                <th>Algorithm</th>
                <th>Matched hash</th>
              </tr>
            </thead>
            <tbody>
              {data.hits.map((hit) => (
                <tr key={`${hit.artifact_id}-${hit.hash_set_id}`}>
                  <td>
                    <Link to={`/cases/${caseId}/artifacts/${hit.artifact_id}`}>
                      {hit.name}
                    </Link>
                  </td>
                  <td>
                    <div className="mono hs-path" title={hit.path}>
                      {hit.path}
                    </div>
                  </td>
                  <td>
                    <span className="badge">{hit.algorithm.toUpperCase()}</span>
                  </td>
                  <td className="mono hs-hash" title={hit.matched_hash}>
                    {truncateHash(hit.matched_hash)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager
            page={page}
            totalPages={totalPages}
            totalCount={data.total}
            onPage={setPage}
          />
        </>
      )}
    </div>
  )
}
