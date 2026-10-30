import { formatUtc } from '../../lib/format'
import type { StatTone } from '../analysis/RichCharts'
import { makeCorrelationPage } from '../correlation/CorrelationPage'
import {
  EXECUTION_TYPES,
  normalizeExecution,
  type ExecEvent,
  type ExecSource,
} from './normalize'

const SOURCE_ORDER: ExecSource[] = [
  'Prefetch',
  'Amcache',
  'Shimcache',
  'Shortcut',
  'Timeline',
]
const SOURCE_TONE: Record<ExecSource, StatTone> = {
  Prefetch: 'accent',
  Amcache: 'ok',
  Shimcache: 'warning',
  Shortcut: 'neutral',
  Timeline: 'critical',
}

/**
 * Unified program-execution evidence. Everything structural — the fan-out, the
 * failure and truncation guards, the incompleteness banner, the case-scoped
 * cross-filters — lives in `makeCorrelationPage`; this file is the vocabulary
 * of the execution view and nothing else.
 */
export const ExecutionPage = makeCorrelationPage<ExecEvent, ExecSource>({
  title: 'Execution evidence',
  intro:
    'Unified program-execution and access evidence, correlated across prefetch, amcache, shimcache, and shortcut (.lnk) artifacts.',
  queryKey: 'execution',
  types: EXECUTION_TYPES,
  normalize: normalizeExecution,
  loadingLabel: 'Correlating prefetch, amcache, shimcache, and shortcuts…',
  subjectNoun: 'execution evidence',
  sourceNoun: 'execution sources',
  recordNoun: 'execution records',
  correlationKeyNoun: 'a program name to correlate on',
  emptyTitle: 'No execution artifacts',
  emptyBody:
    'This case has no prefetch, amcache, shimcache, or shortcut records to correlate.',
  searchPlaceholder: 'Filter by program or path…',
  searchLabel: 'Filter execution events',
  // Fixed source order with a stable tone per source, so the same source is the
  // same colour in every case. Sources with no events get no tile.
  stats: (events) =>
    SOURCE_ORDER.map((s) => ({
      key: s,
      label: s,
      count: events.filter((e) => e.source === s).length,
      tone: SOURCE_TONE[s],
    })).filter((t) => t.count > 0),
  primaryOf: (e) => e.source,
  topTitle: 'Most-referenced programs',
  secondaryOf: (e) => e.program,
  matches: (e, needle) =>
    `${e.program} ${e.fullPath ?? ''}`.toLowerCase().includes(needle),
  timeOf: (e) => e.time,
  artifactIdOf: (e) => e.artifactId,
  rowKey: (e) => `${e.source}-${e.artifactId}`,
  columns: ['Program', 'Source', 'Time (UTC)', 'Detail', 'Path'],
  renderCells: (e) => (
    <>
      <td className="mono">{e.program}</td>
      <td>
        <span className="badge">{e.source}</span>
      </td>
      <td className="mono">
        {e.time != null ? formatUtc(new Date(e.time).toISOString()) : '—'}
      </td>
      <td>{e.detail || '—'}</td>
      <td className="mono">{e.fullPath ?? '—'}</td>
    </>
  ),
})
