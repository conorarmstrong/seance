import { useMemo, useState } from 'react'
import type { ComponentType, ReactNode } from 'react'
import { Phone, PhoneIncoming, PhoneMissed, PhoneOutgoing } from 'lucide-react'
import { formatCount, formatUtc } from '../../lib/format'
import type { ParsedRecord, RecordMetadata } from './api'
import { AggregateEmpty, LoadMoreNote, useAggregatedRecords } from './aggregate'
import { ArtifactLink } from './cells'
import { MISSING, metaNum, metaStr } from './lib'
import { IncompletenessBanner } from '../../components/Incompleteness'
import type { ViewerProps } from './viewers'

/** Which call column the table is ordered by. */
type SortKey = 'direction' | 'contact' | 'timestamp' | 'duration'

/** Per-direction badge styling and icon. Unknown directions fall back below. */
const DIRECTIONS: Record<
  string,
  { label: string; cls: string; Icon: ComponentType<{ size?: number }> }
> = {
  incoming: { label: 'Incoming', cls: 'badge-ok', Icon: PhoneIncoming },
  outgoing: { label: 'Outgoing', cls: 'badge-accent', Icon: PhoneOutgoing },
  missed: { label: 'Missed', cls: 'badge-danger', Icon: PhoneMissed },
}

/** Duration as mm:ss (minutes are not zero-padded). */
function formatDuration(secs: number | null): string {
  if (secs == null || secs < 0) return MISSING
  const m = Math.floor(secs / 60)
  const s = secs % 60
  return `${m}:${String(s).padStart(2, '0')}`
}

/** Call epoch in unix seconds; 0 when absent so it sorts to the bottom. */
function callTime(m: RecordMetadata): number {
  return metaNum(m, 'timestamp') ?? 0
}

function DirectionBadge({ direction }: { direction: string }) {
  const cfg = DIRECTIONS[direction]
  if (!cfg) {
    return (
      <span className="badge an-dir">
        <Phone size={12} />
        {direction || 'unknown'}
      </span>
    )
  }
  const { label, cls, Icon } = cfg
  return (
    <span className={`badge ${cls} an-dir`}>
      <Icon size={12} />
      {label}
    </span>
  )
}

/** Per-direction and total call counts. */
export interface CallCounts {
  total: number
  incoming: number
  outgoing: number
  missed: number
}

/**
 * Derive call counts from the loaded call rows so the summary reflects what is
 * actually in the list. The parser-emitted `*_count` summary metadata is only a
 * fallback for a total the rows can't cover (a truncated/paginated load): with
 * multiple sources it is often a zero/empty record while the table has calls,
 * so trusting it alone shows all zeros (BUG-176).
 */
export function deriveCallCounts(
  calls: ParsedRecord[],
  summaryMeta?: RecordMetadata,
): CallCounts {
  let incoming = 0
  let outgoing = 0
  let missed = 0
  for (const c of calls) {
    switch (metaStr(c.metadata, 'direction')) {
      case 'incoming':
        incoming += 1
        break
      case 'outgoing':
        outgoing += 1
        break
      case 'missed':
        missed += 1
        break
      default:
        break
    }
  }
  // If the parser reported a larger total than the rows we loaded (paginated
  // list), surface that so "Calls" isn't an undercount; the per-direction
  // counts still reflect the loaded rows.
  const parserTotal = summaryMeta ? metaNum(summaryMeta, 'call_count') : null
  const total =
    parserTotal != null && parserTotal > calls.length
      ? parserTotal
      : calls.length
  return { total, incoming, outgoing, missed }
}

/** Summary counts header, derived from the loaded call rows (BUG-176). */
function CallSummary({
  counts,
  platform,
}: {
  counts: CallCounts
  platform: string | null
}) {
  const stats: [string, number][] = [
    ['Calls', counts.total],
    ['Incoming', counts.incoming],
    ['Outgoing', counts.outgoing],
    ['Missed', counts.missed],
  ]
  return (
    <div className="an-summary" data-testid="an-call-summary">
      {stats.map(([label, n]) => (
        <div key={label} className="an-stat">
          <span className="an-stat-num mono">{formatCount(n)}</span>
          <span className="an-stat-label">{label}</span>
        </div>
      ))}
      {platform && <span className="badge an-summary-tag">{platform}</span>}
    </div>
  )
}

/** Column header that toggles the active sort key / direction. */
function SortHeader({
  label,
  col,
  sortKey,
  asc,
  onSort,
}: {
  label: string
  col: SortKey
  sortKey: SortKey
  asc: boolean
  onSort: (col: SortKey) => void
}) {
  const indicator = sortKey === col ? (asc ? ' ▲' : ' ▼') : ''
  return (
    <th aria-sort={sortKey === col ? (asc ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="an-sort" onClick={() => onSort(col)}>
        {label}
        {indicator}
      </button>
    </th>
  )
}

export function CallLogViewer({ caseId, type }: ViewerProps): ReactNode {
  const [sortKey, setSortKey] = useState<SortKey>('timestamp')
  const [asc, setAsc] = useState(false)

  const load = useAggregatedRecords(caseId, type, {
    queryKey: 'analysis-calls',
    loadingLabel: 'Loading calls…',
  })

  const records = load.records
  const summary = records.find((r) => metaStr(r.metadata, 'subtype') === 'summary')
  const calls = useMemo(
    () => records.filter((r) => metaStr(r.metadata, 'subtype') === 'call'),
    [records],
  )
  const counts = useMemo(
    () => deriveCallCounts(calls, summary?.metadata),
    [calls, summary],
  )
  const platform =
    (summary && metaStr(summary.metadata, 'platform')) ??
    (calls[0] ? metaStr(calls[0].metadata, 'platform') : null)

  const sorted = useMemo(() => {
    const dir = asc ? 1 : -1
    const cmp = (a: ParsedRecord, b: ParsedRecord): number => {
      switch (sortKey) {
        case 'direction':
          return (metaStr(a.metadata, 'direction') ?? '').localeCompare(
            metaStr(b.metadata, 'direction') ?? '',
          )
        case 'contact':
          return (metaStr(a.metadata, 'contact') ?? '').localeCompare(
            metaStr(b.metadata, 'contact') ?? '',
          )
        case 'duration':
          return (
            (metaNum(a.metadata, 'duration_seconds') ?? 0) -
            (metaNum(b.metadata, 'duration_seconds') ?? 0)
          )
        default:
          return callTime(a.metadata) - callTime(b.metadata)
      }
    }
    return [...calls].sort((a, b) => cmp(a, b) * dir)
  }, [calls, sortKey, asc])

  const onSort = (col: SortKey) => {
    if (col === sortKey) setAsc((v) => !v)
    else {
      setSortKey(col)
      // Text columns read naturally ascending; numeric columns descending.
      setAsc(col === 'contact' || col === 'direction')
    }
  }

  if (load.gate) return load.gate
  if (calls.length === 0) {
    return (
      <AggregateEmpty
        title="No calls"
        body="No call-log records were parsed for this case."
        loaded={records.length}
        listed={calls.length}
        listedNoun="call row"
      />
    )
  }

  return (
    <div>
      <CallSummary counts={counts} platform={platform} />
      {/* This viewer loads its own records, so the page shell's banner (over its
    page-1 fetch) does not describe what is on screen here. The parsers stamp
    the standard pair on records they could not finish; read it over the set
    this viewer actually holds (B4-023/B4-024). */}
      <IncompletenessBanner summary={load.incompleteness} noun="calls" />
      {load.truncated && (
        <LoadMoreNote
          shown={calls.length}
          total={load.total}
          noun="records"
          onLoadMore={load.loadMore}
        />
      )}
      <table className="data-table an-table">
        <thead>
          <tr>
            <SortHeader label="Direction" col="direction" sortKey={sortKey} asc={asc} onSort={onSort} />
            <SortHeader
              label="Contact / number"
              col="contact"
              sortKey={sortKey}
              asc={asc}
              onSort={onSort}
            />
            <SortHeader label="Time" col="timestamp" sortKey={sortKey} asc={asc} onSort={onSort} />
            <SortHeader label="Duration" col="duration" sortKey={sortKey} asc={asc} onSort={onSort} />
            <th>Platform</th>
            <th>Artifact</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((r) => {
            const m = r.metadata
            const ts = metaNum(m, 'timestamp')
            return (
              <tr key={r.id} tabIndex={0} data-testid="an-call-row">
                <td>
                  <DirectionBadge direction={metaStr(m, 'direction') ?? ''} />
                </td>
                <td className="mono">{metaStr(m, 'contact') ?? metaStr(m, 'number') ?? MISSING}</td>
                <td className="mono">
                  {ts != null ? formatUtc(new Date(ts * 1000).toISOString()) : MISSING}
                </td>
                <td className="mono">{formatDuration(metaNum(m, 'duration_seconds'))}</td>
                <td>{metaStr(m, 'platform') ?? MISSING}</td>
                <td>
                  <ArtifactLink caseId={caseId} id={r.id}>
                    open
                  </ArtifactLink>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
