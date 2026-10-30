import { useQuery } from '@tanstack/react-query'
import { SkeletonTable } from '../../components/Skeleton'
import { useMemo } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { usePivot } from '../../app/PivotContext'
import { Pager } from '../../components/Pager'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { QuickFilterBar, useQuickFilter } from '../../components/QuickFilter'
import { getEntities } from './api'
import { formatCount } from '../../lib/format'
import './entities.css'

const KIND_META: Record<string, { label: string; color: string }> = {
  email: { label: 'Email', color: '#57c08c' },
  messaging_id: { label: 'Messaging ID', color: '#8f7fd4' },
  url: { label: 'URL', color: '#5b9fd4' },
  ipv4: { label: 'IP address', color: '#e5a13c' },
  mac: { label: 'MAC address', color: '#b98cd6' },
  eth: { label: 'Ethereum', color: '#8f9bd6' },
  btc: { label: 'Bitcoin', color: '#d6b84f' },
  credit_card: { label: 'Payment card', color: '#e0785c' },
  phone: { label: 'Phone', color: '#4fb6c0' },
}

const PAGE_SIZE = 100

function kindLabel(kind: string): string {
  return KIND_META[kind]?.label ?? kind
}
function kindColor(kind: string): string {
  return KIND_META[kind]?.color ?? '#9aa3b2'
}

export function EntitiesPage() {
  const { caseId = '' } = useParams()
  const navigate = useNavigate()
  // Both filter the client-side list, and the page stays mounted across a
  // `:caseId` change. Case A's kind filter carried into case B hides every
  // entity of a kind case B does not have, and a page number past case B's end
  // shows nothing — either way the examiner reads "no entities in this case"
  // from a case that has them (B2-019).
  const [kind, setKind] = useEntityScopedState<string | null>(caseId, null)
  const [page, setPage] = useEntityScopedState(caseId, 1)
  const { openPivot } = usePivot()

  const query = useQuery({
    queryKey: ['entities', caseId],
    queryFn: () => getEntities(caseId),
    enabled: caseId !== '',
  })

  const data = query.data
  const kinds = useMemo(
    () =>
      data
        ? Object.entries(data.counts_by_kind).sort((a, b) => b[1] - a[1])
        : [],
    [data],
  )
  const byKind = useMemo(() => {
    const all = data?.entities ?? []
    return kind ? all.filter((e) => e.kind === kind) : all
  }, [data, kind])
  // The quick type-ahead over the value (§1.1), layered on the kind chips: the
  // chips say what sort of identifier, the box says which one. It searches the
  // entities this page holds — which the server caps — so the bar says so.
  const search = useQuickFilter(caseId, byKind, (e) => [e.value, e.kind])
  const filtered = search.rows
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  // The held page can outlive the list it was chosen for: a kind filter, a
  // narrower case, or a refetch that returns fewer entities all shrink the list
  // while the page number stays put, and the table then renders empty under
  // "Page 5 of 1" — which reads as "this case has no entities" (B5-014).
  // Clamped during render so the empty frame never exists.
  const shownPage = Math.min(page, totalPages)
  const pageItems = filtered.slice(
    (shownPage - 1) * PAGE_SIZE,
    shownPage * PAGE_SIZE,
  )

  const selectKind = (k: string | null) => {
    setKind(k)
    setPage(1)
  }

  return (
    <div>
      <h1 className="page-title">Entities</h1>
      <p className="en-sub">
        Identifiers mined from parsed-record text — emails, URLs, IPs, crypto
        addresses, payment cards and more.
      </p>

      {query.isPending ? (
        <SkeletonTable rows={10} cols={4} label="Extracting entities" />
      ) : query.isError ? (
        <div className="error-note">
          Failed to extract entities: {query.error.message}
        </div>
      ) : !data || data.entities.length === 0 ? (
        <div className="empty-state">
          <h3>No entities found</h3>
          <p>
            No emails, URLs, IPs or other identifiers were found in the parsed
            records for this case.
          </p>
        </div>
      ) : (
        <>
          <div className="en-chips">
            <button
              className={kind === null ? 'en-chip active' : 'en-chip'}
              onClick={() => selectKind(null)}
            >
              All
              <span className="en-chip-n">{data.entities.length}</span>
            </button>
            {kinds.map(([k, n]) => (
              <button
                key={k}
                className={kind === k ? 'en-chip active' : 'en-chip'}
                onClick={() => selectKind(k)}
              >
                <i className="en-dot" style={{ background: kindColor(k) }} />
                {kindLabel(k)}
                <span className="en-chip-n">{formatCount(n)}</span>
              </button>
            ))}
          </div>

          <QuickFilterBar
            filter={search}
            noun="value"
            label="Filter entities by value"
            placeholder="Filter by value…"
            // The server scans a bounded number of records and caps the
            // entities it returns, so when it says it capped them this filter
            // searched a subset of the case's identifiers.
            loadedIsSubset={data.truncated}
          />

          <div className="en-meta mono">
            {formatCount(filtered.length)} distinct{' '}
            {kind ? kindLabel(kind).toLowerCase() : 'value'}
            {filtered.length === 1 ? '' : 's'} · scanned{' '}
            {formatCount(data.scanned_records)} records
            {data.truncated ? ' · results capped' : ''}
          </div>

          <div className="fg-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Value</th>
                  <th>Type</th>
                  <th className="en-count-col">Occurrences</th>
                  <th aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {pageItems.map((e) => (
                  <tr key={`${e.kind}:${e.value}`}>
                    <td className="mono en-value">
                      <button
                        className="en-pivot-value"
                        onClick={() => openPivot(e.value)}
                        title="Show every artifact that references this value"
                      >
                        {e.value}
                      </button>
                    </td>
                    <td>
                      <span
                        className="badge en-kind"
                        style={{ color: kindColor(e.kind) }}
                      >
                        {kindLabel(e.kind)}
                      </span>
                    </td>
                    <td className="mono en-count">
                      {formatCount(e.count)}
                    </td>
                    <td className="en-actions">
                      <button
                        className="link-button"
                        onClick={() => openPivot(e.value)}
                      >
                        Pivot
                      </button>
                      <button
                        className="link-button"
                        onClick={() =>
                          navigate(
                            `/cases/${caseId}/search?q=${encodeURIComponent(e.value)}`,
                          )
                        }
                      >
                        Search
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <Pager
            page={shownPage}
            totalPages={totalPages}
            totalCount={filtered.length}
            onPage={setPage}
          />
        </>
      )}
    </div>
  )
}
