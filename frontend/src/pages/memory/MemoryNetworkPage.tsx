import { useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import { getMemoryNetwork, type StageEnvelope } from './api'
import { useMemoryContext } from './memoryContext'
import { LensGate } from './LensState'
import { StageTable, type BlobColumn } from './StageTable'
import { blobNumber, blobString, formatTime, readStageRows } from './normalize'
import { formatCount } from '../../lib/format'

/**
 * Network state recovered from memory.
 *
 * The rows include sockets closed before the capture whose pool allocations
 * survive — usually the interesting ones, and the ones a flat `netstat` on the
 * live machine could never have shown. Because those come out of freed pool the
 * whole lens is graded `scanned`, which is what the confidence column says on
 * every row rather than something an examiner has to remember.
 *
 * Two things are deliberately not done: an address is never resolved to a name
 * from the examination host, and no geolocation is invented. An unresolved
 * address stays an address.
 */

const COLUMNS: BlobColumn[] = [
  {
    id: 'proto',
    header: 'proto',
    render: (data) => blobString(data, 'protocol') ?? blobString(data, 'proto'),
  },
  {
    id: 'local',
    header: 'local',
    mono: true,
    render: (data) => endpoint(data, 'local'),
  },
  {
    id: 'foreign',
    header: 'foreign',
    mono: true,
    render: (data) => endpoint(data, 'foreign') ?? endpoint(data, 'remote'),
  },
  {
    id: 'state',
    header: 'state',
    render: (data) => blobString(data, 'state'),
  },
  {
    id: 'owner',
    header: 'owner',
    mono: true,
    render: (data) => {
      const pid = blobNumber(data, 'pid') ?? blobNumber(data, 'owner_pid')
      // `owner_process` is the key the scan actually emits. It was not in this
      // list, so a row whose owning image the scan DID recover rendered as the
      // literal word "process" beside the pid (B8-040) — indistinguishable from
      // a row whose owner could not be named.
      const name =
        blobString(data, 'owner_process') ??
        blobString(data, 'process_name') ??
        blobString(data, 'owner_name')
      if (pid == null && name == null) return null
      if (name == null) {
        return (
          <>
            <span>{`pid ${pid}`}</span>{' '}
            <span
              className="mem-note"
              title="The scan recovered the owning process id but not its image name. The name is not asserted from the pid: pids are reused, and naming the wrong image here would attribute a connection to a process that never held it."
            >
              (image not named)
            </span>
          </>
        )
      }
      return `${name}${pid != null ? ` (${pid})` : ''}`
    },
  },
  {
    id: 'created',
    header: 'created',
    mono: true,
    render: (data) => {
      const raw =
        blobString(data, 'created') ??
        blobString(data, 'create_time') ??
        blobString(data, 'created_at')
      return raw == null ? null : formatTime(raw)
    },
  },
]

/** `address:port` for one side, or null when neither side was recorded. */
function endpoint(data: Record<string, unknown>, side: string): string | null {
  const address =
    blobString(data, `${side}_address`) ?? blobString(data, `${side}_addr`)
  const port = blobNumber(data, `${side}_port`)
  if (address == null && port == null) return null
  return `${address ?? '?'}:${port ?? '?'}`
}

export function MemoryNetworkPage() {
  const { caseId, imageId, scopeKey } = useMemoryContext()
  const [params, setParams] = useSearchParams()
  const stateFilter = params.get('state')

  const query = useEntityScopedQuery<StageEnvelope>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'network'],
    queryFn: () => getMemoryNetwork(caseId, imageId),
    retry: false,
  })

  const rows = useMemo(
    () => readStageRows(query.scoped, ['connections', 'endpoints', 'entries']),
    [query.scoped],
  )

  const states = useMemo(() => {
    const seen = new Set<string>()
    for (const row of rows) {
      const state = blobString(row.data, 'state')
      if (state != null) seen.add(state)
    }
    return [...seen].sort()
  }, [rows])

  const visible =
    stateFilter == null
      ? rows
      : rows.filter((row) => blobString(row.data, 'state') === stateFilter)

  const setState = (next: string | null) => {
    const updated = new URLSearchParams(params)
    if (next == null) updated.delete('state')
    else updated.set('state', next)
    setParams(updated)
  }

  return (
    <div className="mem-network">
      <div className="page-actions">
        <button
          type="button"
          className={stateFilter == null ? 'btn btn-primary' : 'btn'}
          onClick={() => setState(null)}
        >
          All states
        </button>
        {states.map((state) => (
          <button
            key={state}
            type="button"
            className={stateFilter === state ? 'btn btn-primary' : 'btn'}
            onClick={() => setState(state)}
          >
            {state}
          </button>
        ))}
      </div>

      <LensGate
        label="Network state"
        pending={query.isPending}
        stale={query.stale}
        error={query.isError ? query.error : undefined}
        envelope={query.scoped}
        rowCount={rows.length}
        columns={7}
        emptyTitle="No network structure was recovered"
        emptyReason={
          <>
            The network scan ran and recovered nothing. On a machine that was
            connected this is itself a signal — most often the network symbols
            for this build were unavailable, in which case the capture profile
            says so.{' '}
            <Link
              to={`/cases/${caseId}/memory/image?image=${encodeURIComponent(imageId)}`}
            >
              Check the profile
            </Link>
            .
          </>
        }
      >
        {visible.length === 0 ? (
          <div className="empty-state">
            <h3>No connection in this state</h3>
            <p>
              {formatCount(rows.length)} connection
              {rows.length === 1 ? '' : 's'} were recovered in other states.
              Clear the filter to see them.
            </p>
          </div>
        ) : (
          <StageTable
            rows={visible}
            columns={COLUMNS}
            // Layered on the state chips: the chips say which TCP state, the
            // box says which address or process (§1.1).
            filter={{ scopeId: `netconn-${imageId}`, noun: 'connection' }}
          />
        )}
      </LensGate>
    </div>
  )
}
