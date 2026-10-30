import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import {
  getMemoryProcesses,
  getProcessHandles,
  type MemoryProcessesResponse,
  type StageEnvelope,
} from './api'
import { useMemoryContext } from './memoryContext'
import { ConfidenceChip } from './confidence'
import { LensGate } from './LensState'
import { FieldCell, StageTable, type BlobColumn } from './StageTable'
import { formatCount } from '../../lib/format'
import {
  blobString,
  fieldText,
  hexAddress,
  readProcesses,
  readStageRows,
  readWireTextOf,
} from './normalize'

/**
 * Handles, one process at a time.
 *
 * A Windows capture holds 100k to 500k handles and the analysis emits them as
 * one table per process, so that is how they are served and that is how they
 * are shown. This page is deliberately **not** a case-wide handle list: there
 * is no endpoint that produces one, and paging a client-side merge of every
 * process's table would silently show a sample of the whole while looking like
 * the whole.
 *
 * The selected process is a URL parameter, so a handle table is a citable
 * address rather than a place you have to navigate back to.
 */

const COLUMNS: BlobColumn[] = [
  {
    id: 'type',
    header: 'type',
    render: (data) =>
      blobString(data, 'object_type') ?? blobString(data, 'type_name'),
  },
  {
    id: 'name',
    header: 'object',
    mono: true,
    // The analysis sends the name as an envelope — `{kind:"name", name}`,
    // `{kind:"unnamed"}` or `{kind:"unavailable", detail}` — because "this
    // mutant has no name" and "the bytes holding the name would not read" are
    // different facts. Read as a plain string it decoded to null on every real
    // row, so every file path, key path and target process the handle walk
    // recovered rendered as "not recorded" (B8-037).
    render: (data) => (
      <FieldCell field={readWireTextOf(data, ['name', 'object_name'])} />
    ),
  },
  {
    id: 'handle',
    header: 'handle',
    mono: true,
    render: (data) => hexAddress(data, 'handle_value'),
  },
  {
    id: 'access',
    header: 'granted access',
    mono: true,
    render: (data) =>
      hexAddress(data, 'granted_access') ??
      blobString(data, 'granted_access'),
  },
]

export function MemoryHandlesPage() {
  const { caseId, imageId, scopeKey } = useMemoryContext()
  const [params, setParams] = useSearchParams()
  const pidParam = params.get('pid')
  const pid = pidParam != null && /^\d+$/.test(pidParam) ? Number(pidParam) : null

  const processQuery = useEntityScopedQuery<MemoryProcessesResponse>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'processes'],
    queryFn: () => getMemoryProcesses(caseId, imageId),
    retry: false,
  })
  const processes = useMemo(
    () => readProcesses(processQuery.scoped?.list),
    [processQuery.scoped],
  )

  const handlesQuery = useEntityScopedQuery<StageEnvelope>(
    `${scopeKey}/${pid ?? 'none'}`,
    {
      queryKey: ['memory', caseId, imageId, 'process-handles', pid],
      queryFn: () =>
        pid == null
          ? Promise.reject(new Error('no process selected'))
          : getProcessHandles(caseId, imageId, pid),
      enabled: pid != null,
      retry: false,
    },
  )
  const rows = useMemo(
    () => readStageRows(handlesQuery.scoped, ['handles', 'entries']),
    [handlesQuery.scoped],
  )

  const selectPid = (next: number | null) => {
    const updated = new URLSearchParams(params)
    if (next == null) updated.delete('pid')
    else updated.set('pid', String(next))
    setParams(updated)
  }

  return (
    <div className="mem-handles">
      <LensGate
        label="Processes"
        pending={processQuery.isPending}
        stale={processQuery.stale}
        error={processQuery.isError ? processQuery.error : undefined}
        envelope={processQuery.scoped?.list}
        rowCount={processes.length}
        columns={4}
        emptyTitle="No process was recovered"
        emptyReason="Handles are read per process, and no process was recovered from this capture, so there is nothing to open a handle table for."
      >
        <div className="page-actions">
          <label className="mem-search">
            <span>Process</span>
            <select
              className="select"
              value={pid ?? ''}
              onChange={(event) =>
                selectPid(
                  event.target.value === '' ? null : Number(event.target.value),
                )
              }
            >
              <option value="">Choose a process…</option>
              {processes
                .filter((row) => row.pid.known)
                .map((row) => (
                  <option
                    key={row.key}
                    value={row.pid.known ? row.pid.value : undefined}
                  >
                    {fieldText(row.name)} ({fieldText(row.pid)}) ·{' '}
                    {fieldText(row.handles)} handles
                  </option>
                ))}
            </select>
          </label>
          {processes.some((row) => !row.pid.known) && (
            <span className="mem-note">
              Some recovered processes have no readable id and cannot be looked
              up. They are not hidden from the process lens.
            </span>
          )}
        </div>

        {pid == null ? (
          <div className="empty-state">
            <h3>Choose a process</h3>
            <p>
              The analysis reads handle tables one process at a time, and a
              Windows capture holds hundreds of thousands of handles in total.
              Picking a process here loads that process&rsquo;s table from the
              server; nothing is sampled.
            </p>
          </div>
        ) : (
          <LensGate
            label="Handles"
            pending={handlesQuery.isPending}
            stale={handlesQuery.stale}
            error={handlesQuery.isError ? handlesQuery.error : undefined}
            envelope={handlesQuery.scoped}
            rowCount={rows.length}
            columns={5}
            emptyTitle="This process held no handle"
            emptyReason="The handle table was read and was empty. A live process normally holds at least a handful, so treat an empty table as a fact about the capture rather than about the process."
          >
            <div className="mem-handles-head">
              <span className="mem-note">
                {formatCount(rows.length)} handle
                {rows.length === 1 ? '' : 's'} for pid {pid}
              </span>
              {rows[0] != null && <ConfidenceChip confidence={rows[0].confidence} />}
            </div>
            <StageTable
              rows={rows}
              columns={COLUMNS}
              // Held against the process, not the capture: a needle typed on
              // one process's handles is about that process, and carrying it
              // to the next would show an empty table for a process that has
              // handles.
              filter={{ scopeId: `handles-${pid}`, noun: 'handle' }}
            />
          </LensGate>
        )}
      </LensGate>
    </div>
  )
}
