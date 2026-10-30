import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import {
  getMemoryCrossview,
  getMemoryProcesses,
  type MemoryProcessesResponse,
  type StageEnvelope,
} from './api'
import { useMemoryContext } from './memoryContext'
import { AgreementGlyph, ConfidenceChip, ConfidenceHeader } from './confidence'
import { LensGate } from './LensState'
import { ProcessInspector } from './ProcessInspector'
import { formatCount } from '../../lib/format'
import {
  buildProcessRows,
  envelopeStatus,
  fieldText,
  fieldTitle,
  formatQualifiedCount,
  PARENT_LINK_MEANING,
  presenceFor,
  readCrossview,
  readProcesses,
  readTreeNodes,
  timeText,
  type CrossviewRow,
  type ParentLinkKind,
  type ProcessRow,
  terminated,
} from './normalize'

/**
 * The process tree: the centre of gravity of memory analysis.
 *
 * It answers in one view what upstream needs six plugins and a manual diff to
 * answer: what was running, what has exited, and — the part no flat list can
 * show — **which enumeration strategies agree**. The presence glyph on each row
 * turns that agreement into ambient information, with a third state for a
 * strategy that did not run, because a crashed scanner must never read as "this
 * process is hidden".
 *
 * The hierarchy is the *analysis's* tree, not one rebuilt here from parent ids.
 * The analysis knows which edges it could confirm and which it refused to draw;
 * re-deriving parentage in the browser would silently reinstate every edge it
 * declined, including the ones a reissued process id makes false.
 */

/** Edges the analysis could not stand behind, and the badge each earns. */
const LINK_TONE: Record<ParentLinkKind, string> = {
  confirmed: '',
  root: '',
  unverified: 'badge badge-warn',
  ambiguous: 'badge badge-warn',
  orphaned: 'badge badge-warn',
  cycle: 'badge badge-danger',
  unknown: 'badge badge-warn',
}

export function ProcessTreePage() {
  const { caseId, imageId, scopeKey } = useMemoryContext()
  const [params, setParams] = useSearchParams()
  const pidParam = params.get('pid')
  const selectedPid =
    pidParam != null && /^\d+$/.test(pidParam) ? Number(pidParam) : null

  const [search, setSearch] = useEntityScopedState(scopeKey, '')

  const processQuery = useEntityScopedQuery<MemoryProcessesResponse>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'processes'],
    queryFn: () => getMemoryProcesses(caseId, imageId),
    retry: false,
  })
  const crossviewQuery = useEntityScopedQuery<StageEnvelope>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'crossview'],
    queryFn: () => getMemoryCrossview(caseId, imageId),
    retry: false,
  })

  const data = processQuery.scoped
  const crossview = useMemo(
    () => readCrossview(crossviewQuery.scoped),
    [crossviewQuery.scoped],
  )

  const crossviewByPid = useMemo(() => {
    const map = new Map<number, CrossviewRow>()
    // A duplicate PID in the cross-view keeps the first row rather than
    // overwriting: merging two processes' presence vectors would invent
    // agreement no strategy reported.
    for (const row of crossview.rows) {
      if (row.pid != null && !map.has(row.pid)) map.set(row.pid, row)
    }
    return map
  }, [crossview])

  const processes = useMemo(
    () =>
      readProcesses(data?.list, (pid) => {
        if (pid == null) return null
        const row = crossviewByPid.get(pid)
        return crossview.methods
          .filter((method) => presenceFor(method, row) === 'seen')
          .map((method) => method.label)
      }),
    [data, crossview, crossviewByPid],
  )
  const nodes = useMemo(() => readTreeNodes(data?.tree), [data])
  const treeRows = useMemo(
    () => buildProcessRows(processes, nodes),
    [processes, nodes],
  )

  const needle = search.trim().toLowerCase()
  const visible = useMemo(() => {
    if (needle === '') return treeRows
    return treeRows.filter((entry) => rowSearchText(entry.row).includes(needle))
  }, [treeRows, needle])

  const selected =
    selectedPid == null
      ? null
      : (processes.find(
          (row) => row.pid.known && row.pid.value === selectedPid,
        ) ?? null)

  const setParam = (key: string, value: string | null) => {
    const next = new URLSearchParams(params)
    if (value == null) next.delete(key)
    else next.set(key, value)
    setParams(next)
  }

  const treeStatus = envelopeStatus(data?.tree)
  const crossviewStatus = envelopeStatus(crossviewQuery.scoped)
  const exited = processes.filter((row) => row.hasExited).length
  const unreadable = processes.filter(
    (row) => row.unreadableFields.length > 0,
  ).length

  return (
    <div className="mem-processes">
      <div className="page-actions">
        <label className="mem-search">
          <span className="mem-visually-hidden">Search processes</span>
          <input
            className="input"
            type="search"
            placeholder="name or pid"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>
        {data != null && (
          <span className="mem-note">
            {formatQualifiedCount(processes.length, [
              { count: exited, label: 'exited' },
              { count: unreadable, label: 'with unreadable fields' },
            ])}
          </span>
        )}
      </div>

      {crossviewQuery.isSuccess && crossviewStatus.kind === 'not_run' && (
        <div className="error-note" role="note">
          <strong>The cross-view comparison did not run.</strong>{' '}
          {terminated(crossviewStatus.message)} Presence marks are therefore unknown for
          every row, and the absence of a concealment badge below means nothing.
        </div>
      )}
      {crossview.methods
        .filter((method) => !method.ran)
        .map((method) => (
          <div className="warn-note" role="note" key={method.key}>
            <strong>{method.label} did not run.</strong>{' '}
            {method.error ?? 'The analysis gave no reason.'} Its mark is shown as
            not checked rather than as &ldquo;not seen&rdquo;.
          </div>
        ))}

      {treeStatus.kind === 'not_run' && (
        <div className="warn-note" role="note">
          <strong>No parent/child structure was derived.</strong>{' '}
          {treeStatus.message} The rows below are the flat list; no hierarchy is
          drawn, because drawing one from parent ids alone would assert edges the
          analysis refused.
        </div>
      )}

      <div className="mem-process-layout">
        <div className="mem-process-main">
          <LensGate
            label="Processes"
            pending={processQuery.isPending}
            stale={processQuery.stale}
            error={processQuery.isError ? processQuery.error : undefined}
            envelope={data?.list}
            rowCount={treeRows.length}
            columns={6}
            emptyTitle="No process was recovered"
            emptyReason="Process enumeration ran and found nothing. On a Windows capture that is itself an anomaly — even an idle machine runs System, smss and csrss — so treat it as a fact about the capture or the profile, not about the machine."
          >
            {visible.length === 0 ? (
              <div className="empty-state">
                <h3>No process matches this search</h3>
                <p>
                  {formatCount(processes.length)} process
                  {processes.length === 1 ? '' : 'es'} were recovered. Clear the
                  search to see them.
                </p>
              </div>
            ) : (
              <table
                className="data-table mem-process-table"
                // A treegrid, not a tree: the rows are a table of facts *and* a
                // hierarchy, and `aria-level` on a row is only meaningful
                // inside one.
                role={nodes.length > 0 ? 'treegrid' : undefined}
                aria-label={nodes.length > 0 ? 'Process tree' : undefined}
              >
                <thead>
                  <tr>
                    <ConfidenceHeader />
                    <th
                      scope="col"
                      title="Which enumeration strategies saw this row"
                    >
                      Seen by
                    </th>
                    <th scope="col">Process</th>
                    <th scope="col">PID</th>
                    <th scope="col">Created</th>
                    <th scope="col">Exited</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((entry) => {
                    const row = entry.row
                    const pid = row.pid.known ? row.pid.value : null
                    return (
                      <tr
                        key={row.key}
                        aria-level={
                          nodes.length > 0 ? entry.depth + 1 : undefined
                        }
                        aria-selected={
                          nodes.length > 0 ? pid === selectedPid : undefined
                        }
                        className={[
                          pid != null && pid === selectedPid ? 'selected' : '',
                          entry.link === 'cycle' ? 'mem-row-hidden' : '',
                          row.unreadableFields.length > 0
                            ? 'mem-row-flagged'
                            : '',
                        ]
                          .filter(Boolean)
                          .join(' ')}
                      >
                        <td>
                          <ConfidenceChip
                            confidence={row.confidence}
                            provenance={[
                              { label: 'EPROCESS', value: row.address },
                              { label: 'reached by', value: row.direction },
                            ]}
                          />
                        </td>
                        <td>
                          <AgreementGlyph
                            methods={crossview.methods}
                            row={
                              pid == null ? undefined : crossviewByPid.get(pid)
                            }
                          />
                        </td>
                        <td style={{ paddingLeft: 10 + entry.depth * 14 }}>
                          {pid == null ? (
                            <span
                              className="mono mem-note"
                              title={fieldTitle(row.pid)}
                            >
                              {fieldText(row.name)} (pid {fieldText(row.pid)})
                            </span>
                          ) : (
                            <button
                              type="button"
                              className="link-button mono"
                              onClick={() => setParam('pid', String(pid))}
                            >
                              {fieldText(row.name)}
                            </button>
                          )}
                          {LINK_TONE[entry.link] !== '' && (
                            <span
                              className={LINK_TONE[entry.link]}
                              title={`${PARENT_LINK_MEANING[entry.link]}${entry.linkDetail ? ` ${entry.linkDetail}` : ''}`}
                            >
                              {entry.link} parent
                            </span>
                          )}
                          {row.unreadableFields.length > 0 && (
                            <span
                              className="badge badge-warn"
                              title={`Unreadable: ${row.unreadableFields.join(', ')}`}
                            >
                              {row.unreadableFields.length} unreadable field
                              {row.unreadableFields.length === 1 ? '' : 's'}
                            </span>
                          )}
                        </td>
                        <td className="mono" title={fieldTitle(row.pid)}>
                          {fieldText(row.pid)}
                        </td>
                        <td className="mono" title={fieldTitle(row.createTime)}>
                          {timeText(row.createTime)}
                        </td>
                        <td className="mono" title={fieldTitle(row.exitTime)}>
                          {timeText(row.exitTime)}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </LensGate>
        </div>

        {selected != null && (
          <ProcessInspector
            caseId={caseId}
            imageId={imageId}
            scopeKey={scopeKey}
            process={selected}
            onClose={() => setParam('pid', null)}
          />
        )}
        {selectedPid != null && selected == null && !processQuery.isPending && (
          <div className="warn-note" role="note">
            <strong>No recovered process has pid {selectedPid}.</strong> The
            address selects a process this capture does not contain, so nothing
            is shown rather than the nearest match.
          </div>
        )}
      </div>
    </div>
  )
}

/** Lower-cased haystack for the search box: name, pid and kernel address. */
function rowSearchText(row: ProcessRow): string {
  const name = row.name.known ? row.name.value : ''
  const pid = row.pid.known ? String(row.pid.value) : ''
  return `${name} ${pid} ${row.address}`.toLowerCase()
}
