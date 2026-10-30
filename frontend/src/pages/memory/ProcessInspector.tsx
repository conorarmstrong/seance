import { useMemo } from 'react'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import {
  getProcessHandles,
  getProcessModules,
  getProcessVads,
  type StageEnvelope,
} from './api'
import { ConfidenceChip } from './confidence'
import { LensGate } from './LensState'
import { FieldCell, StageTable, type BlobColumn } from './StageTable'
import { formatCount } from '../../lib/format'
import {
  blobBool,
  blobNumber,
  blobString,
  fieldLeaf,
  fieldText,
  fieldTitle,
  hexAddress,
  readStageRows,
  readWireTextOf,
  timeText,
  type Field,
  type ProcessRow,
} from './normalize'

/**
 * The per-process inspector.
 *
 * Its job is to remove the joins an examiner would otherwise do by hand: the
 * process arrives already carrying its modules, its handles and its address
 * map, so "which plugin owns this fact" never comes up. Each tab fetches only
 * when it is opened, and each renders the same states as every other lens — a
 * tab whose stage did not run says so rather than showing an empty table under
 * a process that plainly has DLLs loaded.
 */

type TabKey = 'overview' | 'modules' | 'handles' | 'map'

const TABS: { key: TabKey; label: string }[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'modules', label: 'DLLs' },
  { key: 'handles', label: 'Handles' },
  { key: 'map', label: 'Memory map' },
]

export function ProcessInspector({
  caseId,
  imageId,
  scopeKey,
  process,
  onClose,
}: {
  caseId: string
  imageId: string
  scopeKey: string
  process: ProcessRow
  onClose: () => void
}) {
  const pid = process.pid.known ? process.pid.value : null
  // Scoped to the process as well as the capture: a tab selected on one process
  // must not carry over to a process where that tab means something else.
  const [tab, setTab] = useEntityScopedState<TabKey>(
    `${scopeKey}/${pid ?? 'unknown'}`,
    'overview',
  )

  return (
    <aside
      className="mem-inspector"
      aria-label={`Process ${pid ?? 'with no readable id'} inspector`}
    >
      <header className="mem-inspector-head">
        <h2 className="mem-inspector-title">
          {fieldText(process.name)}{' '}
          <span className="mono">pid {fieldText(process.pid)}</span>
        </h2>
        <ConfidenceChip
          confidence={process.confidence}
          provenance={[{ label: 'EPROCESS', value: process.address }]}
        />
        <button type="button" className="btn" onClick={onClose}>
          Close
        </button>
      </header>

      <div className="mem-tabs" role="tablist" aria-label="Process detail">
        {TABS.map((entry) => (
          <button
            key={entry.key}
            type="button"
            role="tab"
            aria-selected={tab === entry.key}
            className={tab === entry.key ? 'mem-tab active' : 'mem-tab'}
            onClick={() => setTab(entry.key)}
          >
            {entry.label}
          </button>
        ))}
      </div>

      <div className="mem-tabpanel" role="tabpanel">
        {tab === 'overview' && <OverviewTab process={process} />}
        {pid == null && tab !== 'overview' && (
          <div className="warn-note" role="note">
            This process&rsquo;s id could not be read, and every per-process
            lookup is keyed on it. Nothing is fetched rather than fetching
            another process&rsquo;s rows.
          </div>
        )}
        {pid != null && tab === 'modules' && (
          <ModulesTab
            caseId={caseId}
            imageId={imageId}
            scopeKey={scopeKey}
            pid={pid}
          />
        )}
        {pid != null && tab === 'handles' && (
          <HandlesTab
            caseId={caseId}
            imageId={imageId}
            scopeKey={scopeKey}
            pid={pid}
          />
        )}
        {pid != null && tab === 'map' && (
          <MemoryMapTab
            caseId={caseId}
            imageId={imageId}
            scopeKey={scopeKey}
            pid={pid}
          />
        )}
      </div>
    </aside>
  )
}

function OverviewTab({ process }: { process: ProcessRow }) {
  return (
    <dl className="mem-kv">
      <div className="mem-kv-row">
        <dt>EPROCESS</dt>
        <dd className="mono">{process.address}</dd>
      </div>
      <div className="mem-kv-row">
        <dt>reached by</dt>
        <dd className="mono">{process.direction}</dd>
      </div>
      <div className="mem-kv-row">
        <dt>parent id</dt>
        <dd className="mono" title={fieldTitle(process.ppid)}>
          {fieldText(process.ppid)}
        </dd>
      </div>
      <div className="mem-kv-row">
        <dt>created</dt>
        <dd className="mono" title={fieldTitle(process.createTime)}>
          {timeText(process.createTime)}
        </dd>
      </div>
      <div className="mem-kv-row">
        <dt>exited</dt>
        <dd className="mono" title={fieldTitle(process.exitTime)}>
          {timeText(process.exitTime)}
        </dd>
      </div>
      <div className="mem-kv-row">
        <dt>session</dt>
        <dd className="mono" title={fieldTitle(process.sessionId)}>
          {fieldText(process.sessionId)}
        </dd>
      </div>
      <div className="mem-kv-row">
        <dt>threads</dt>
        <dd className="mono" title={fieldTitle(process.threads)}>
          {fieldText(process.threads)}
        </dd>
      </div>
      <div className="mem-kv-row">
        <dt>handles</dt>
        <dd className="mono" title={fieldTitle(process.handles)}>
          {fieldText(process.handles)}
        </dd>
      </div>
      {process.unreadableFields.length > 0 && (
        <div className="mem-kv-row">
          <dt>unreadable</dt>
          <dd>
            <span className="badge badge-warn">
              {process.unreadableFields.join(', ')}
            </span>
            <span className="mem-note">
              {' '}
              These fields exist on this build and their bytes could not be
              read. They are named rather than left blank.
            </span>
          </dd>
        </div>
      )}
      {process.notes.length > 0 && (
        <div className="mem-kv-row">
          <dt>notes</dt>
          <dd>
            <ul className="mem-steps">
              {process.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          </dd>
        </div>
      )}
    </dl>
  )
}

/**
 * The file a module row names.
 *
 * The per-process module walk identifies each image by the file mapped into its
 * range, and sends that as an envelope (`mapped_file`) rather than as a string:
 * a range with no file behind it is a finding, not a missing name. The flat
 * keys are the kernel-module walk's aliases, kept so both shapes render.
 */
function moduleFile(data: Record<string, unknown>): Field<string> {
  return readWireTextOf(data, [
    'mapped_file',
    'full_path',
    'full_dll_name',
    'path',
    'base_name',
    'name',
    'base_dll_name',
  ])
}

const MODULE_COLUMNS: BlobColumn[] = [
  {
    id: 'name',
    header: 'module',
    mono: true,
    render: (data) => <FieldCell field={fieldLeaf(moduleFile(data))} />,
  },
  {
    id: 'path',
    header: 'path',
    mono: true,
    render: (data) => <FieldCell field={moduleFile(data)} />,
  },
  {
    id: 'base',
    header: 'base',
    mono: true,
    // `base_hex` is the exact form; the number is rounded above 2^53 and every
    // x64 module base is. Fall back to the number only when no sibling exists.
    render: (data) => hexAddress(data, 'base') ?? hexAddress(data, 'dll_base'),
  },
]

function ModulesTab({
  caseId,
  imageId,
  scopeKey,
  pid,
}: {
  caseId: string
  imageId: string
  scopeKey: string
  pid: number
}) {
  const query = useEntityScopedQuery<StageEnvelope>(`${scopeKey}/${pid}`, {
    queryKey: ['memory', caseId, imageId, 'process-modules', pid],
    queryFn: () => getProcessModules(caseId, imageId, pid),
    retry: false,
  })
  const rows = useMemo(
    () => readStageRows(query.scoped, ['modules', 'entries']),
    [query.scoped],
  )
  return (
    <LensGate
      label="Loaded modules"
      pending={query.isPending}
      stale={query.stale}
      error={query.isError ? query.error : undefined}
      envelope={query.scoped}
      rowCount={rows.length}
      columns={4}
      emptyTitle="No module was recovered for this process"
      emptyReason="The loader lists were walked and carried no entry. For a live user-mode process that is itself anomalous: every such process loads at least ntdll."
    >
      <StageTable
        rows={rows}
        columns={MODULE_COLUMNS}
        // Held against the process: a needle typed on one process's modules is
        // about that process (§1.1).
        filter={{ scopeId: `modules-${pid}`, noun: 'module' }}
      />
    </LensGate>
  )
}

const HANDLE_COLUMNS: BlobColumn[] = [
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
    // Envelope, not a string — see the same column on MemoryHandlesPage
    // (B8-037). Read flat, every named handle rendered "not recorded".
    render: (data) => (
      <FieldCell field={readWireTextOf(data, ['name', 'object_name'])} />
    ),
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

function HandlesTab({
  caseId,
  imageId,
  scopeKey,
  pid,
}: {
  caseId: string
  imageId: string
  scopeKey: string
  pid: number
}) {
  const query = useEntityScopedQuery<StageEnvelope>(`${scopeKey}/${pid}`, {
    queryKey: ['memory', caseId, imageId, 'process-handles', pid],
    queryFn: () => getProcessHandles(caseId, imageId, pid),
    retry: false,
  })
  const rows = useMemo(
    () => readStageRows(query.scoped, ['handles', 'entries']),
    [query.scoped],
  )
  return (
    <LensGate
      label="Handles"
      pending={query.isPending}
      stale={query.stale}
      error={query.isError ? query.error : undefined}
      envelope={query.scoped}
      rowCount={rows.length}
      columns={4}
      emptyTitle="This process held no handle"
      emptyReason="The handle table was read and was empty. A live process normally holds at least a handful, so treat an empty table as a fact about the capture rather than about the process."
    >
      <StageTable
        rows={rows}
        columns={HANDLE_COLUMNS}
        filter={{ scopeId: `proc-handles-${pid}`, noun: 'handle' }}
      />
    </LensGate>
  )
}

/**
 * The memory-map tab.
 *
 * The detail that carries the value: a region backed by no file and mapped
 * writable *and* executable is called out, because code loaded by the normal
 * loader is file-backed and is not both. The call-out is a signal, never a
 * verdict — legitimate JIT engines allocate exactly this.
 */
/**
 * How the region is protected, as an examiner reads it.
 *
 * The walk sends `protection_names` (the decoded string) beside `protection`
 * (the raw index). This column used to read `protection` as a string, which it
 * never is, so it was blank on every row — and the writable+executable
 * call-out below, which is the reason the column exists, could not fire at all.
 * The raw index alone is reported as such rather than dressed up as a
 * protection: without the kernel's table it names nothing.
 */
function regionProtection(data: Record<string, unknown>): string | null {
  const names =
    blobString(data, 'protection_names') ??
    blobString(data, 'protection_name') ??
    blobString(data, 'protection')
  if (names != null) return names
  const index = blobNumber(data, 'protection')
  return index == null ? null : `protection index ${index}, not decoded`
}

/** The file mapped into the region, as an envelope (`{kind:"no_mapped_file"}`
 *  is the unbacked finding, not a missing value). */
function regionBacking(data: Record<string, unknown>): Field<string> {
  return readWireTextOf(data, ['file', 'file_name', 'backing_file'])
}

/**
 * Whether the region is *established* to have no file behind it.
 *
 * Only an explicit "no mapped file", or the walk's own `private_memory` flag,
 * counts. A backing field that could not be read is not evidence of absence,
 * and the flag it feeds is close to an accusation.
 */
function regionUnbacked(data: Record<string, unknown>): boolean {
  const backing = regionBacking(data)
  if (backing.known) return false
  return backing.reason === 'none' || blobBool(data, 'private_memory') === true
}

/** Writable, executable, and established to be backed by no file. */
function regionFlagged(data: Record<string, unknown>): boolean {
  const protection = regionProtection(data)
  return (
    protection != null &&
    /EXECUTE/i.test(protection) &&
    /WRITE/i.test(protection) &&
    regionUnbacked(data)
  )
}

const REGION_COLUMNS: BlobColumn[] = [
  {
    id: 'range',
    header: 'range',
    mono: true,
    render: (data) => {
      const start = hexAddress(data, 'start') ?? hexAddress(data, 'start_va')
      const end = hexAddress(data, 'end') ?? hexAddress(data, 'end_va')
      if (start == null && end == null) return null
      return `${start ?? '?'} – ${end ?? '?'}`
    },
  },
  {
    id: 'protection',
    header: 'protection',
    mono: true,
    render: (data) => {
      const protection = regionProtection(data)
      if (protection == null) return null
      return (
        <>
          <span>{protection}</span>
          {regionFlagged(data) && (
            <span
              className="badge badge-danger"
              title="Writable and executable with no file behind it. Code loaded by the normal loader is file-backed and is not both. This is a signal to corroborate, not a verdict — JIT engines allocate the same shape."
            >
              writable + executable, unbacked
            </span>
          )}
        </>
      )
    },
  },
  {
    id: 'backing',
    header: 'backing file',
    mono: true,
    render: (data) => {
      const backing = regionBacking(data)
      if (!backing.known && backing.reason === 'none') {
        return 'private, no file'
      }
      if (!backing.known && blobBool(data, 'private_memory') === true) {
        return 'private, no file'
      }
      return <FieldCell field={backing} />
    },
  },
  { id: 'tag', header: 'tag', field: 'tag', mono: true },
]

function MemoryMapTab({
  caseId,
  imageId,
  scopeKey,
  pid,
}: {
  caseId: string
  imageId: string
  scopeKey: string
  pid: number
}) {
  const query = useEntityScopedQuery<StageEnvelope>(`${scopeKey}/${pid}`, {
    queryKey: ['memory', caseId, imageId, 'process-vads', pid],
    queryFn: () => getProcessVads(caseId, imageId, pid),
    retry: false,
  })
  const rows = useMemo(
    () => readStageRows(query.scoped, ['regions', 'vads', 'entries']),
    [query.scoped],
  )
  return (
    <LensGate
      label="Memory map"
      pending={query.isPending}
      stale={query.stale}
      error={query.isError ? query.error : undefined}
      envelope={query.scoped}
      rowCount={rows.length}
      columns={5}
      emptyTitle="No region was enumerated for this process"
      emptyReason="The address-space walk completed and produced no region. Every live process has at least its image and its stack, so an empty map points at the capture or at the walk, not at the process."
    >
      <p className="mem-note">
        {formatCount(rows.length)} region{rows.length === 1 ? '' : 's'}. A
        range absent from the capture is reported by the analysis as unreadable
        and is never rendered as zeros.
      </p>
      <StageTable
        rows={rows}
        columns={REGION_COLUMNS}
        rowClassName={(data) =>
          regionFlagged(data) ? 'mem-row-flagged' : undefined
        }
        filter={{ scopeId: `regions-${pid}`, noun: 'region' }}
      />
    </LensGate>
  )
}
