import { useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Q_KEYS_MAX, type ParsedRecord, type RecordMetadata } from './api'
import {
  SEARCH_DEBOUNCE_MS,
  useDebounced,
  useRecordPages,
} from './recordPages'
import { toEpochMs } from '../../lib/epoch'
import { formatCount, formatUtc } from '../../lib/format'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { useInfiniteScroll } from '../../lib/useInfiniteScroll'
import { ArtifactLink, toIso, type Column } from './cells'
import { MISSING, metaBool, metaFirst, metaNum, metaStr } from './lib'
import { RecordTable, type RecordTableSort } from './RecordTable'

import { ChartScopeNote, SearchScopeNote } from './searchScope'
import { StatTiles, TimeHistogram, TopBars, type StatTone } from './RichCharts'
import {
  IncompletenessBanner,
  useIncompleteness,
} from '../../components/Incompleteness'
import { ScopeBadge, ScopeNote } from '../../components/MeasuredScope'
import {
  APP_ID_RAW_SCOPE,
  CLIPBOARD_TEXT_SCOPE,
} from '../../lib/measuredScope'
import type { ViewerProps } from './viewers'

/** Records fetched per scroll step (mirrors the Rich viewers). */
const RECORD_PAGE_SIZE = 200

/**
 * Metadata keys the Filter box's term is tested against, server-side. The
 * endpoint refuses `q` without them; they are the fields an examiner hunting a
 * document name, an executable, a URL or a copied string would expect to reach.
 */
const SEARCH_KEYS = [
  'display_text',
  'executable',
  'content_uri',
  'clipboard_text',
  'app_display_name',
].slice(0, Q_KEYS_MAX)

// ---------------------------------------------------------------------------
// Activity-type classification (advisory labels; see documentation/WINDOWS_DESIGN.md, Windows Timeline)
// ---------------------------------------------------------------------------

type KindKey = 'focus' | 'open' | 'clipboard' | 'system' | 'other'

const KIND_META: Record<
  KindKey,
  { label: string; tone: StatTone; badge: string }
> = {
  focus: { label: 'Focus', tone: 'accent', badge: 'badge badge-accent' },
  open: { label: 'Open', tone: 'ok', badge: 'badge badge-ok' },
  clipboard: { label: 'Clipboard', tone: 'critical', badge: 'badge badge-danger' },
  system: { label: 'System', tone: 'warning', badge: 'badge' },
  other: { label: 'Other', tone: 'neutral', badge: 'badge' },
}

const KIND_ORDER: KindKey[] = ['focus', 'open', 'clipboard', 'system', 'other']

/** Bucket a record by its (advisory) ActivityType code. */
function kindOf(m: RecordMetadata): KindKey {
  const t = metaNum(m, 'activity_type')
  if (t === 6) return 'focus'
  if (t === 5) return 'open'
  if (t === 10 || t === 16) return 'clipboard'
  if (t === 11 || t === 12 || t === 15) return 'system'
  return 'other'
}

/** True when the activity synced from another signed-in device. */
function isCrossDevice(m: RecordMetadata): boolean {
  const cloud = metaNum(m, 'created_in_cloud')
  if (cloud != null && cloud > 0) return true
  const local = metaNum(m, 'is_local_only')
  return local === 0
}

// ---------------------------------------------------------------------------
// Small formatting helpers
// ---------------------------------------------------------------------------

/** Last path segment of a Windows or POSIX path. */
function lastSegment(path: string | null): string | null {
  if (!path) return null
  const parts = path.split(/[\\/]/).filter(Boolean)
  return parts.length ? parts[parts.length - 1] : path
}

/** Compact duration: "45s", "3m 20s", "1h 04m". */
function formatDuration(secs: number | null): string {
  if (secs == null || secs <= 0) return MISSING
  const h = Math.floor(secs / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = secs % 60
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`
  if (m > 0) return `${m}m ${String(s).padStart(2, '0')}s`
  return `${s}s`
}

/** Friendly application label: display name, else the executable basename. */
function appLabel(m: RecordMetadata): string | null {
  const app = metaStr(m, 'app_display_name')
  if (app) return app
  const exe = metaStr(m, 'executable')
  return exe ? (lastSegment(exe) ?? exe) : null
}

/** Content target label: host for URLs, basename for file paths. */
function docLabel(m: RecordMetadata): string | null {
  const uri = metaStr(m, 'content_uri')
  if (!uri) return null
  try {
    const u = new URL(uri)
    if (u.protocol === 'http:' || u.protocol === 'https:') return u.hostname || uri
  } catch {
    /* not a parseable URL — fall through to path handling */
  }
  return lastSegment(uri) ?? uri
}

/** A timestamp rendered as UTC, or the missing dash. */
function utcCell(m: RecordMetadata, keys: string[]): string {
  const raw = metaFirst(m, keys)
  return raw == null ? MISSING : formatUtc(toIso(raw))
}

/** Duration in seconds preferring the wall-clock span, then active focus time. */
function durationSecs(m: RecordMetadata): number | null {
  return metaNum(m, 'duration_seconds') ?? metaNum(m, 'active_duration_seconds')
}

interface TopRow {
  label: string
  count: number
}

function topBy(
  records: ParsedRecord[],
  value: (m: RecordMetadata) => string | null,
): TopRow[] {
  const counts = new Map<string, number>()
  for (const r of records) {
    const label = value(r.metadata)
    if (label == null) continue
    counts.set(label, (counts.get(label) ?? 0) + 1)
  }
  return Array.from(counts, ([label, count]) => ({ label, count }))
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

/**
 * The ordering an examiner arrives on: the most recent activity first.
 *
 * It is the SERVER's ordering. The old table re-sorted whatever rows had been
 * fetched, so "Start ▼" over an ActivitiesCache.db with more activities than
 * one page meant "the newest of the two hundred rows loaded so far" while
 * reading as "the newest activity on this device" — a false answer to the first
 * question anyone asks of a timeline. Sorting is a query parameter now, so the
 * top row is the top row of the type.
 *
 * The keys below are the metadata keys the server orders on, which is not
 * always the value the cell renders: the Application cell falls back to the
 * executable's basename and the Duration cell falls back to the active-focus
 * span. `RecordTable` puts the key on the sort control's tooltip rather than
 * letting the heading imply it.
 */
const DEFAULT_SORT: RecordTableSort = { key: 'start_time', order: 'desc' }


// ---------------------------------------------------------------------------
// Detail panel — decoded payload, clipboard reveal, times, identities
// ---------------------------------------------------------------------------

function DetailRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="an-wt-section">
      <div className="an-wt-section-title">{title}</div>
      {children}
    </div>
  )
}

interface AppPackage {
  platform?: unknown
  name?: unknown
}

function ActivityDetail({
  record,
  caseId,
  onClose,
}: {
  record: ParsedRecord
  caseId: string
  onClose: () => void
}): ReactNode {
  const m = record.metadata
  const kind = kindOf(m)
  // Each disclosure is consent to see ONE activity's raw content: the
  // clipboard capture, the unresolved AppId, the raw payload. Scoped to the
  // record so selecting the next activity re-masks them. Clearing them in a
  // `useEffect` keyed on `record.id` did not: the effect runs after the frame
  // in which `record` is already the new activity has been committed, so the
  // next row's clipboard text was painted unmasked — revealed by a click the
  // examiner made against a different record.
  const [reveal, setReveal] = useEntityScopedState(record.id, false)
  const [showRawAppId, setShowRawAppId] = useEntityScopedState(record.id, false)
  const [showRawJson, setShowRawJson] = useEntityScopedState(record.id, false)

  const app = appLabel(m) ?? MISSING
  const start = utcCell(m, ['start_time', 'date'])
  const end = utcCell(m, ['end_time'])
  const tz = metaStr(m, 'user_timezone')
  const contentUri = metaStr(m, 'content_uri')
  const activationUri = metaStr(m, 'activation_uri')
  const clipText = metaStr(m, 'clipboard_text')
  const packages = Array.isArray(m['packages'])
    ? (m['packages'] as AppPackage[])
    : []

  return (
    <aside
      className="an-wt-detail"
      data-testid="an-wt-detail"
      aria-label="Activity detail"
    >
      <div className="an-wt-detail-head">
        <span className="an-wt-detail-app mono" title={metaStr(m, 'executable') ?? undefined}>
          {app}
        </span>
        <span className={KIND_META[kind].badge}>
          {metaStr(m, 'activity_type_label') ?? KIND_META[kind].label}
        </span>
        {isCrossDevice(m) && <span className="badge badge-accent">cloud</span>}
        <button
          type="button"
          className="an-wt-detail-close"
          aria-label="Close detail"
          onClick={onClose}
        >
          ×
        </button>
      </div>
      <div className="an-wt-detail-range mono">
        {start} → {end} ({formatDuration(durationSecs(m))})
      </div>
      <div className="an-wt-detail-src">
        source: <span className="badge">{metaStr(m, 'source_table') ?? 'Activity'}</span>
      </div>

      <Section title="What">
        <dl className="an-kv">
          <DetailRow label="Display text" value={metaStr(m, 'display_text') ?? MISSING} />
          <DetailRow label="Description" value={metaStr(m, 'description') ?? MISSING} />
          <DetailRow label="App" value={metaStr(m, 'app_display_name') ?? MISSING} />
        </dl>
      </Section>

      <Section title="Target">
        <dl className="an-kv">
          <DetailRow
            label="Content URI"
            value={<span className="mono an-wt-uri">{contentUri ?? MISSING}</span>}
          />
          <DetailRow
            label="Activation URI"
            value={<span className="mono an-wt-uri">{activationUri ?? MISSING}</span>}
          />
        </dl>
      </Section>

      {kind === 'clipboard' && (
        <Section title="Clipboard">
          <div className="an-wt-clip-meta">
            format: {metaStr(m, 'clipboard_format') ?? 'Text'} · decoded from base64
            {/* The parser cuts the captured text at a storage cap and says so on
                `clipboard_text_truncated`. Shown on the meta line, not only
                beside the revealed text: an examiner who never clicks Reveal
                would otherwise be told nothing about what was cut. */}
            {clipText ? (
              <>
                {' '}
                <ScopeBadge metadata={m} spec={CLIPBOARD_TEXT_SCOPE} />
              </>
            ) : null}
          </div>
          {clipText ? (
            reveal ? (
              <>
                <div className="an-wt-clip-text mono">{clipText}</div>
                <ScopeNote metadata={m} spec={CLIPBOARD_TEXT_SCOPE} />
              </>
            ) : (
              <button
                type="button"
                className="link-button"
                aria-expanded={false}
                onClick={() => setReveal(true)}
              >
                Reveal clipboard text
              </button>
            )
          ) : (
            <div className="an-wt-clip-meta">{MISSING}</div>
          )}
        </Section>
      )}

      <Section title="Times (UTC)">
        <dl className="an-kv">
          <DetailRow label="Start" value={<span className="mono">{start}</span>} />
          <DetailRow label="End" value={<span className="mono">{end}</span>} />
          <DetailRow
            label="Duration"
            value={<span className="mono">{formatDuration(metaNum(m, 'duration_seconds'))}</span>}
          />
          <DetailRow
            label="Active duration"
            value={
              <span className="mono">{formatDuration(metaNum(m, 'active_duration_seconds'))}</span>
            }
          />
          <DetailRow
            label="Last modified"
            value={<span className="mono">{utcCell(m, ['last_modified_time'])}</span>}
          />
          <DetailRow
            label="Modified on client"
            value={<span className="mono">{utcCell(m, ['last_modified_on_client'])}</span>}
          />
          <DetailRow
            label="Created in cloud"
            value={<span className="mono">{utcCell(m, ['created_in_cloud'])}</span>}
          />
          <DetailRow
            label="Expiration"
            value={<span className="mono">{utcCell(m, ['expiration_time'])}</span>}
          />
        </dl>
        {tz && <div className="an-wt-tz">device local zone: {tz}</div>}
      </Section>

      {packages.length > 0 && (
        <Section title="App identities">
          <dl className="an-kv">
            {packages.map((p, i) => (
              <DetailRow
                key={i}
                label={String(p.platform ?? '?')}
                value={<span className="mono an-wt-uri">{String(p.name ?? MISSING)}</span>}
              />
            ))}
          </dl>
          {metaStr(m, 'app_id_raw') && (
            <>
              <button
                type="button"
                className="link-button"
                aria-expanded={showRawAppId}
                onClick={() => setShowRawAppId((v) => !v)}
              >
                {showRawAppId ? 'Hide raw AppId' : 'Show raw AppId'}
              </button>{' '}
              {/* The blob is cut at a storage cap (`app_id_raw_truncated`), and
                  the identities past the cut are not in it. */}
              <ScopeBadge metadata={m} spec={APP_ID_RAW_SCOPE} />
              {showRawAppId && (
                <>
                  <pre className="an-wt-raw mono">{metaStr(m, 'app_id_raw')}</pre>
                  <ScopeNote metadata={m} spec={APP_ID_RAW_SCOPE} />
                </>
              )}
            </>
          )}
        </Section>
      )}

      <div className="an-wt-detail-actions">
        <ArtifactLink caseId={caseId} id={record.id}>
          View artifact
        </ArtifactLink>
        <button
          type="button"
          className="link-button"
          aria-expanded={showRawJson}
          onClick={() => setShowRawJson((v) => !v)}
        >
          {showRawJson ? 'Hide raw JSON' : 'Raw JSON'}
        </button>
      </div>
      {showRawJson && (
        <pre className="an-wt-raw mono">{JSON.stringify(m, null, 2)}</pre>
      )}
    </aside>
  )
}

// ---------------------------------------------------------------------------
// Table columns
// ---------------------------------------------------------------------------

/**
 * The activity table, as columns for the shared record table.
 *
 * `sortKey` is present only where the whole record type can be put in order on
 * one metadata key. "Display text" and "Content / URI" each read the first of
 * two keys, so neither is one thing the server could sort on; offering a header
 * that re-sorted the loaded rows instead would be the very trap this viewer was
 * moved off its own table to lose.
 */
const TIMELINE_COLUMNS: Column[] = [
  {
    key: 'app',
    header: 'Application',
    sortKey: 'app_display_name',
    render: (m) => (
      <span className="mono" title={metaStr(m, 'executable') ?? undefined}>
        {appLabel(m) ?? MISSING}
      </span>
    ),
  },
  {
    key: 'activity',
    header: 'Activity',
    sortKey: 'activity_type_label',
    render: (m) => (
      <span className={KIND_META[kindOf(m)].badge}>
        {metaStr(m, 'activity_type_label') ?? KIND_META[kindOf(m)].label}
      </span>
    ),
  },
  {
    key: 'display_text',
    header: 'Display text',
    render: (m) => (
      <span
        className="an-trunc"
        title={metaFirst(m, ['display_text', 'name']) ?? undefined}
      >
        {metaFirst(m, ['display_text', 'name']) ?? MISSING}
      </span>
    ),
  },
  {
    key: 'uri',
    header: 'Content / URI',
    render: (m) => {
      const uri = metaFirst(m, ['content_uri', 'activation_uri'])
      return (
        <span className="mono an-trunc" title={uri ?? undefined}>
          {uri ?? MISSING}
        </span>
      )
    },
  },
  {
    key: 'start',
    header: 'Start',
    sortKey: 'start_time',
    sortDefaultOrder: 'desc',
    render: (m) => (
      <span className="mono">{utcCell(m, ['start_time', 'date'])}</span>
    ),
  },
  {
    key: 'end',
    header: 'End',
    sortKey: 'end_time',
    sortDefaultOrder: 'desc',
    render: (m) => <span className="mono">{utcCell(m, ['end_time'])}</span>,
  },
  {
    key: 'duration',
    header: 'Duration',
    sortKey: 'duration_seconds',
    sortDefaultOrder: 'desc',
    render: (m) => (
      <span className="mono">{formatDuration(durationSecs(m))}</span>
    ),
  },
  {
    key: 'device',
    header: 'Device',
    render: (m) => (
      <>
        {metaStr(m, 'device_platform') ?? MISSING}
        {isCrossDevice(m) && (
          <span className="badge badge-accent an-wt-cloud">cloud</span>
        )}
      </>
    ),
  },
  {
    key: 'clip',
    header: 'Clip',
    render: (m) =>
      metaBool(m, 'has_clipboard') ? (
        <span className="badge badge-danger">clipboard</span>
      ) : null,
  },
]

/**
 * Why a row is worth a second look, or null. A clipboard capture is the content
 * of something the user copied; a cloud-synced activity happened on a device
 * that may not be the one in evidence. Both are stated rather than left as a
 * colour, because a highlight nobody can read is not a finding.
 */
function notableReason(m: RecordMetadata): string | null {
  const clip = metaBool(m, 'has_clipboard')
  const cross = isCrossDevice(m)
  if (clip && cross) {
    return 'Carries a clipboard capture, and synced from another signed-in device'
  }
  if (clip) return 'Carries a clipboard capture'
  if (cross) return 'Synced from another signed-in device'
  return null
}

// ---------------------------------------------------------------------------
// The viewer
// ---------------------------------------------------------------------------

export function WindowsTimelineViewer({ caseId, type }: ViewerProps): ReactNode {
  const [stat, setStat] = useState<KindKey | null>(null)
  const [dim, setDim] = useState<{ title: string; label: string } | null>(null)
  const [search, setSearch] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [sort, setSort] = useState<RecordTableSort>(DEFAULT_SORT)

  // Held back until typing settles: every distinct term is a fresh query key
  // and therefore a fresh request.
  const term = useDebounced(search.trim(), SEARCH_DEBOUNCE_MS)
  const searching = term.length > 0

  // The term and the ordering are both part of the query key. Either one
  // changed is a different question of the server, and its answer has to
  // replace the previous one's pages rather than be appended to them — which is
  // also what puts paging back at page 1 whenever either changes.
  const {
    query,
    records: all,
    total,
    typeTotal,
    unfilterable,
    qMatch,
  } = useRecordPages({
    caseId,
    type,
    pageSize: RECORD_PAGE_SIZE,
    q: searching ? term : undefined,
    qKeys: searching ? SEARCH_KEYS : undefined,
    sort: sort.key ?? undefined,
    order: sort.order,
    queryKey: [
      'rich-records',
      type,
      caseId,
      searching ? term : null,
      sort.key,
      sort.order,
    ],
  })

  const loadedCount = all.length
  const incompleteness = useIncompleteness(all)

  // Pull the next page when the sentinel scrolls into view (button is the
  // no-IntersectionObserver fallback that jsdom tests click).
  const endRef = useRef<HTMLDivElement>(null)
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = query
  useInfiniteScroll(endRef, {
    hasNextPage,
    isFetchingNextPage,
    onLoadMore: fetchNextPage,
  })

  // Stat tiles computed over the whole loaded set so they stay stable while a
  // filter is active. Only non-empty buckets get a tile.
  const stats = useMemo(() => {
    const counts = new Map<KindKey, number>()
    for (const r of all) {
      const k = kindOf(r.metadata)
      counts.set(k, (counts.get(k) ?? 0) + 1)
    }
    return KIND_ORDER.filter((k) => (counts.get(k) ?? 0) > 0).map((k) => ({
      key: k,
      label: KIND_META[k].label,
      count: counts.get(k) ?? 0,
      tone: KIND_META[k].tone,
    }))
  }, [all])

  // The term is NOT re-applied here, and neither is the ordering: the server
  // did both, over every activity of this type, and the rows arrive matching
  // and in order. What is left are the stat tile and the bar row, which are
  // cross-filters over the rows loaded so far — which is what `ChartScopeNote`
  // says they are.
  const visible = useMemo(() => {
    if (!stat && !dim) return all
    return all.filter((r) => {
      const m = r.metadata
      if (stat && kindOf(m) !== stat) return false
      if (dim) {
        const label = dim.title === 'Top applications' ? appLabel(m) : docLabel(m)
        if (label !== dim.label) return false
      }
      return true
    })
  }, [all, stat, dim])

  const times = useMemo(
    () =>
      visible
        .map((r) => toEpochMs(r.metadata, ['start_time', 'date']))
        .filter((t): t is number => t != null),
    [visible],
  )

  const topApps = useMemo(() => topBy(visible, appLabel), [visible])
  const topDocs = useMemo(() => topBy(visible, docLabel), [visible])

  const selected = useMemo(
    () => all.find((r) => r.id === selectedId) ?? null,
    [all, selectedId],
  )

  // Clicking the active column reverses it; a new column starts in whichever
  // direction that column is usually read in.
  const onSort = (key: string) =>
    setSort((cur) =>
      cur.key === key
        ? { key, order: cur.order === 'asc' ? 'desc' : 'asc' }
        : {
            key,
            order:
              TIMELINE_COLUMNS.find((c) => c.sortKey === key)
                ?.sortDefaultOrder ?? 'asc',
          },
    )

  // The toolbar has to survive a search or a re-sort. Either is a new query
  // key, so react-query reports `isPending` again — and an early return on that
  // would unmount the Filter box mid-word and throw away the caret, the term
  // and the sort controls. Once anything has loaded the shell stays, and only
  // the results area below it says that a query is running.
  const everLoaded = useRef(false)
  if (query.data) everLoaded.current = true

  if (query.isError) {
    return <div className="error-note">{(query.error as Error).message}</div>
  }
  if (query.isPending && !everLoaded.current) {
    return <div className="loading">Loading Windows Timeline activity…</div>
  }
  // "The feature was disabled on this device" is a finding about the evidence,
  // so it is allowed only when nothing was asked of the server but the type. A
  // term that matched nothing is an empty RESULT, and printing this under it
  // would turn a filter into a false absence.
  if (!searching && !query.isPending && all.length === 0) {
    return (
      <div className="empty-state">
        <h3>No Windows Timeline activity</h3>
        <p>
          This evidence has no ActivitiesCache.db, or the Windows Timeline /
          Activity History feature was disabled on this device.
        </p>
      </div>
    )
  }

  const crossFiltered = stat != null || dim != null
  // The charts are still browser-side, so they describe the loaded rows
  // whenever fewer have been fetched than the query matched.
  const partial = loadedCount < total

  return (
    <div className="rv an-wt">
      {/* This viewer loads its own records, so the page shell's banner (over its
          page-1 fetch) does not describe what is on screen here. The parsers
          stamp the standard pair on records they could not finish; read it over
          the set this viewer actually holds (B4-023/B4-024). */}
      <IncompletenessBanner
        summary={incompleteness}
        noun="Windows Timeline activities"
      />
      <div className="rv-toolbar">
        <input
          className="input rv-search"
          placeholder="Filter by document, app, URL, or clipboard…"
          aria-label="Filter Windows Timeline activity"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <span className="rv-count">
          {/* A count of the RENDERED rows. A stat tile or a bar row narrows the
              loaded set in the browser, so both halves of this reading are
              about loaded rows and it says so; the populations of the case are
              in the notes below. */}
          {crossFiltered
            ? `${formatCount(visible.length)} of ${formatCount(all.length)} loaded rows shown`
            : `${formatCount(visible.length)} shown`}
        </span>
        {(crossFiltered || searching) && (
          <button
            type="button"
            className="link-button"
            onClick={() => {
              setStat(null)
              setDim(null)
              setSearch('')
            }}
          >
            Clear filters
          </button>
        )}
        <span className="rv-note">
          {formatCount(loadedCount)} of {formatCount(total)}
          {searching ? ' matching' : ''} loaded
        </span>
      </div>

      {searching && !query.isPending && (
        <SearchScopeNote
          term={term}
          keys={SEARCH_KEYS}
          matching={total}
          typeTotal={typeTotal}
          unfilterable={unfilterable}
          match={qMatch}
          noun="activities"
        />
      )}

      {query.isPending ? (
        <div className="loading">Searching Windows Timeline activity…</div>
      ) : all.length === 0 ? (
        // A term that matched nothing. The sentence above already names both
        // populations, so this only has to be an empty state that does not read
        // as absence from the device.
        <div className="empty-state">
          <h3>No matching activities</h3>
          <p>
            No activities in this case match &ldquo;{term}&rdquo;. Clear the
            filter to see all {formatCount(typeTotal)}.
          </p>
        </div>
      ) : (
        <>
          {partial && (
            <ChartScopeNote
              loaded={loadedCount}
              total={total}
              noun="activities"
              filtered={searching}
            />
          )}

          <StatTiles
            tiles={stats}
            active={stat}
            onToggle={(k) => setStat((cur) => (cur === k ? null : (k as KindKey)))}
          />

          <TimeHistogram times={times} />

          <div className="rv-dims">
            <TopBars
              title="Top applications"
              items={topApps}
              active={dim?.title === 'Top applications' ? dim.label : null}
              onSelect={(label) =>
                setDim((cur) =>
                  cur && cur.title === 'Top applications' && cur.label === label
                    ? null
                    : { title: 'Top applications', label },
                )
              }
            />
            <TopBars
              title="Top documents / URLs"
              items={topDocs}
              active={dim?.title === 'Top documents / URLs' ? dim.label : null}
              onSelect={(label) =>
                setDim((cur) =>
                  cur && cur.title === 'Top documents / URLs' && cur.label === label
                    ? null
                    : { title: 'Top documents / URLs', label },
                )
              }
            />
          </div>

          <div className="an-wt-layout">
            <div className="an-wt-main">
              <div className="an-wt-table-wrap">
                {/* The shared record table: a windowed DOM, one tab stop, arrow-key
                    movement and `aria-rowindex` over every row it holds. This used
                    to be a hand-written table, which is to say a table with none of
                    those. Selection is passed in and out rather than kept inside,
                    so the detail panel beside it follows the keyboard as well as
                    the mouse. */}
                <RecordTable
                  records={visible}
                  caseId={caseId}
                  columns={TIMELINE_COLUMNS}
                  notable={notableReason}
                  className="rv-table"
                  rowClassName="an-wt-row"
                  rowTestId="an-wt-row"
                  selectedId={selectedId}
                  onSelect={(r) => setSelectedId(r.id)}
                  sort={sort}
                  onSort={onSort}
                />
              </div>
              <div ref={endRef} className="rv-sentinel">
                {hasNextPage && (
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => void fetchNextPage()}
                    disabled={isFetchingNextPage}
                  >
                    {isFetchingNextPage ? 'Loading more…' : 'Load more'}
                  </button>
                )}
              </div>
            </div>

            {selected && (
              <ActivityDetail
                record={selected}
                caseId={caseId}
                onClose={() => setSelectedId(null)}
              />
            )}
          </div>
        </>
      )}
    </div>
  )
}
