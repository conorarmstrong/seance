import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { QuickFilterBar, useQuickFilter } from '../../components/QuickFilter'
import { useTimeWindow } from '../../app/TimeWindowContext'
import { SkeletonTable } from '../../components/Skeleton'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import type { QueryParams } from '../../api/http'
import {
  createTimelineTag,
  createVirtualColumn,
  deleteTimelineTag,
  deleteVirtualColumn,
  getTimeline,
  getTimelineModules,
  getVirtualColumns,
  updateTimelineTag,
} from '../../api/resources'
import type { TimelineEvent, VirtualColumnDef } from '../../api/types'
import { Pager } from '../../components/Pager'
import { SavedViewsMenu } from '../../components/SavedViewsMenu'
import { useToast } from '../../components/toast/ToastProvider'
import { exportTerminator } from '../search/api'
import { downloadFile } from '../../lib/download'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { ActivityHeatmap } from './ActivityHeatmap'
import { ActivityHistogram } from './ActivityHistogram'
import { TimelineSwimlanes } from './TimelineSwimlanes'
import { type AnalysisFilter, isFnEvent, timestompHint } from './analysis'
import {
  getTimelineActivity,
  getTimelineHistogram,
  getTimelineSwimlanes,
} from './api'
import { ColumnSettingsModal } from './ColumnSettingsModal'
import { EventsTable } from './EventsTable'
import { TagNoteModal } from './TagNoteModal'
import { TimelineToolbar, type ExportFormat } from './Toolbar'

const EXPORT_EXTENSION: Record<ExportFormat, string> = {
  json: 'json',
  csv: 'csv',
  pdf: 'pdf',
  sqlite: 'sqlite',
  body_events: 'body.txt',
}
import './timeline.css'

const HISTOGRAM_BUCKETS = 120
/** Max in-flight requests during a bulk tag/untag run. */
const BULK_CONCURRENCY = 4

const COLUMNS_STORAGE_PREFIX = 'seance_timeline_columns'

/** The empty bulk selection, as one shared value so that scoping the selection
 * back to "nothing selected" returns a stable reference. Never mutated: every
 * update below builds a new Set. */
const NO_SELECTION: Set<string> = new Set()

/** Virtual-column visibility is per-case, like Saved Views: scope the key by
 * case so opening case B does not inherit case A's visible column ids. */
function columnsStorageKey(caseId: string): string {
  return `${COLUMNS_STORAGE_PREFIX}.${caseId}`
}

function loadStoredColumns(caseId: string): string[] | null {
  try {
    const raw = localStorage.getItem(columnsStorageKey(caseId))
    return raw ? (JSON.parse(raw) as string[]) : null
  } catch {
    return null
  }
}

function slugId(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return `vc_${slug || 'column'}_${Date.now()}`
}

export function TimelinePage() {
  const { caseId = '' } = useParams<{ caseId: string }>()
  const toast = useToast()
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()

  // ---- URL state ----
  const page = Math.max(1, Number(searchParams.get('page') ?? '1') || 1)
  const pageSize = Number(searchParams.get('page_size') ?? '100') || 100
  const search = searchParams.get('search') ?? ''
  const range = searchParams.get('range') ?? ''
  const from = searchParams.get('from')
  const to = searchParams.get('to')
  const modules = searchParams.get('modules')?.split(',').filter(Boolean) ?? []
  const taggedOnly = searchParams.get('tagged_only') === 'true'
  const sortBy = searchParams.get('sort_by') ?? 'timestamp'
  const sortOrder = searchParams.get('sort_order') ?? 'desc'
  const chartParam = searchParams.get('chart')
  const chartView =
    chartParam === 'swimlanes'
      ? 'swimlanes'
      : chartParam === 'heatmap'
        ? 'heatmap'
        : 'activity'

  /** Patch URL params; empty/null values delete the key. Filter changes reset the page. */
  const updateParams = (
    patch: Record<string, string | null>,
    resetPage = true,
  ) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      for (const [key, value] of Object.entries(patch)) {
        if (value === null || value === '') next.delete(key)
        else next.set(key, value)
      }
      if (resetPage && !('page' in patch)) next.delete('page')
      return next
    })
  }

  // ---- Visible virtual columns (persisted per case to localStorage) ----
  // The preference is per case and this page stays mounted when `:caseId`
  // changes. Reloading it in an effect was one render too late: the first paint
  // under case B still used case A's column ids, and a toggle inside that window
  // wrote case A's selection into case B's localStorage key. Reading the stored
  // preference during render, and only trusting the held copy while it still
  // belongs to this case, closes the window (B2-022).
  const storedForCase = useMemo(() => loadStoredColumns(caseId), [caseId])
  const [heldColumns, setHeldColumns] = useState<{
    case: string
    ids: string[]
  } | null>(null)
  const storedColumnIds =
    heldColumns && heldColumns.case === caseId ? heldColumns.ids : storedForCase
  const setVisibleColumnIds = (ids: string[]) => {
    setHeldColumns({ case: caseId, ids })
    localStorage.setItem(columnsStorageKey(caseId), JSON.stringify(ids))
  }

  const columnsQuery = useQuery({
    queryKey: ['virtual-columns', caseId],
    queryFn: () => getVirtualColumns(caseId),
  })
  // Memoized so their array identities are stable across unrelated re-renders
  // (e.g. a selection toggle): visibleColumns is a prop to every memoized row,
  // so a fresh array each render would defeat that memoization.
  const virtualColumns = useMemo(
    () => columnsQuery.data?.virtual_columns ?? [],
    [columnsQuery.data],
  )
  const visibleColumnIds = useMemo(
    () =>
      storedColumnIds ??
      virtualColumns.filter((c) => c.default_visible).map((c) => c.id),
    [storedColumnIds, virtualColumns],
  )
  const visibleColumns = useMemo(
    () => virtualColumns.filter((c) => visibleColumnIds.includes(c.id)),
    [virtualColumns, visibleColumnIds],
  )
  const columnPaths = [
    ...new Set(visibleColumns.flatMap((c) => c.sources.map((s) => s.path))),
  ].join(',')

  // The case-wide window from the persistent bar (§1.1), layered UNDER this
  // page's own `from`/`to`.
  //
  // The local window wins, and the order matters: the examiner set the local
  // one on the screen in front of them, by brushing this page's own chart,
  // while the global one was set elsewhere and followed them here. Letting the
  // global one override a brush would make the chart on this page unable to
  // change what the page shows.
  //
  // Whichever is in force, the page says which — see `windowNote` below. A
  // narrowed page that did not would present a subset as the case.
  const { window: caseWindow } = useTimeWindow()
  const localWindow = from != null || to != null || range !== ''
  const effectiveFrom = localWindow ? from : caseWindow?.from.toString() ?? null
  const effectiveTo = localWindow ? to : caseWindow?.to.toString() ?? null

  // ---- Timeline data ----
  const baseFilters: QueryParams = {
    search: search || undefined,
    range: range || undefined,
    from: effectiveFrom ?? undefined,
    to: effectiveTo ?? undefined,
    modules: modules.length > 0 ? modules.join(',') : undefined,
    tagged_only: taggedOnly ? true : undefined,
  }
  const filterParams: QueryParams = {
    ...baseFilters,
    sort_by: sortBy,
    sort_order: sortOrder,
  }
  // The server only recomputes the filtered COUNT(*) when we ask (count !=
  // false). The total is invariant while paging within one filter set, so we
  // ask on page 1 or whenever the filters changed, and reuse the cached total
  // (below) while paging. `filterKey` intentionally excludes page and columns,
  // which never change the count. It DOES include caseId: two cases can carry
  // the same filters, and without caseId a placeholder kept from case A (same
  // filters) would tag-match case B and render A's events/total under B's
  // chrome, and poison the count cache (BUG-195).
  const filterKey = JSON.stringify({ caseId, ...filterParams })
  const countCacheRef = useRef<{
    key: string
    total_count: number
    total_pages: number
  } | null>(null)
  const wantCount = page === 1 || countCacheRef.current?.key !== filterKey

  const timelineParams: QueryParams = {
    ...filterParams,
    page,
    page_size: pageSize,
    columns: columnPaths || undefined,
    count: wantCount ? undefined : false,
  }

  const timelineQuery = useQuery({
    queryKey: ['timeline', caseId, timelineParams],
    // Tag each response with the filter identity so a placeholder left over from
    // a different filter (kept by placeholderData below) can be told apart from
    // the previous page of the same filter, which stays on screen for smooth
    // paging.
    queryFn: async () => ({
      ...(await getTimeline(caseId, timelineParams)),
      _filterKey: filterKey,
    }),
    placeholderData: (prev) => prev,
  })

  // Identity of the chart filter set. `placeholderData` keeps the previous
  // filter's chart on screen during the refetch; tagging each response lets the
  // render tell a stale placeholder apart from the current filter's data so the
  // histogram/swimlanes never show the previous filter's distribution under the
  // new chrome (BUG-168) -- the same guard the event table already uses.
  // caseId is part of the identity so a case A -> case B switch with identical
  // filters gates A's chart buckets rather than tag-matching them onto B
  // (BUG-195).
  const chartFilterKey = JSON.stringify({ caseId, ...baseFilters })

  const histogramQuery = useQuery({
    queryKey: ['timeline-histogram', caseId, baseFilters],
    queryFn: async () => ({
      ...(await getTimelineHistogram(caseId, {
        ...baseFilters,
        buckets: HISTOGRAM_BUCKETS,
        // Draw where the events are, at a bucket width chosen for that window
        // rather than for an extent one artefactual 1980 timestamp can stretch
        // across four decades (UI-010). The server does the narrowing, and
        // returns what it left out so the chart can say so.
        focus: 'auto',
      })),
      _filterKey: chartFilterKey,
    }),
    placeholderData: (prev) => prev,
  })

  const swimlanesQuery = useQuery({
    queryKey: ['timeline-swimlanes', caseId, baseFilters],
    queryFn: async () => ({
      ...(await getTimelineSwimlanes(caseId, {
        ...baseFilters,
        buckets: HISTOGRAM_BUCKETS,
        // The same window as the histogram above it, derived the same way, so
        // the two charts of one case on one screen share an axis.
        focus: 'auto',
      })),
      _filterKey: chartFilterKey,
    }),
    enabled: chartView === 'swimlanes',
    placeholderData: (prev) => prev,
  })

  const staleHistogram =
    histogramQuery.data != null &&
    histogramQuery.data._filterKey !== chartFilterKey
  const staleSwimlanes =
    swimlanesQuery.data != null &&
    swimlanesQuery.data._filterKey !== chartFilterKey

  const activityQuery = useQuery({
    queryKey: ['timeline-activity', caseId],
    queryFn: () => getTimelineActivity(caseId),
    enabled: chartView === 'heatmap',
  })

  const modulesQuery = useQuery({
    queryKey: ['timeline-modules', caseId],
    queryFn: () => getTimelineModules(caseId),
  })

  // ---- Modals ----
  const [columnsModalOpen, setColumnsModalOpen] = useState(false)
  // The route param can change without remounting this page. A tag/note modal
  // left open would still hold case A's event while the chrome is case B, and
  // Save posts to `/cases/<caseB>/timeline/<eventIdFromA>` — a write against
  // the wrong case (BUG-266).
  //
  // Closing it from a `useEffect` keyed on the case is one commit too late: the
  // switching render paints the dialog, still holding case A's event, over case
  // B's timeline, and a Save clicked on that frame is sent to case B. Scoping
  // the open event to the case resolves it during render, so the dialog is
  // already gone in the first frame under the new case (B2-148).
  const [noteEvent, setNoteEvent] = useEntityScopedState<TimelineEvent | null>(
    caseId,
    null,
  )

  // ---- Export busy state ----
  const [exporting, setExporting] = useState<ExportFormat | null>(null)

  // ---- Client-side analysis filter (loaded page only) ----
  // Trims the rendered page to filename-anomaly or timestomp candidates. Left
  // set across a `:caseId` change it silently hides most of case B's events,
  // which reads as "case B has almost no activity" rather than as an active
  // filter the examiner chose for another case (B2-028).
  const [analysisFilter, setAnalysisFilter] = useEntityScopedState<AnalysisFilter>(
    caseId,
    'all',
  )

  // ---- Bulk selection ----
  // Selection is scoped to the exact slice on screen. caseId is part of that
  // identity: two cases can carry identical filters, and a selection carried
  // across the switch would bulk-tag case A's event ids under case B (BUG-266).
  //
  // Clearing it from a `useEffect` left one committed frame showing "N
  // selected" over case B's timeline while `selectedIds` still held case A's
  // event ids, and Tag/Untag clicked on that frame POSTs those ids to case B.
  // Resolving the selection against the slice during render closes the window
  // instead of repairing it afterwards (B2-148).
  const timelineParamsKey = JSON.stringify({ caseId, ...timelineParams })
  const [selectedIds, setSelectedIds] = useEntityScopedState<Set<string>>(
    `${timelineParamsKey}|${analysisFilter}`,
    NO_SELECTION,
  )
  const [bulkProgress, setBulkProgress] = useState<{
    done: number
    total: number
  } | null>(null)

  // ---- Mutations ----
  // Every write below targets the case that was open when `mutate()` ran, but
  // `onSuccess` runs in the latest render's closure. Reading `caseId` there
  // refreshed whichever case is on screen when the response lands, leaving the
  // case that actually changed showing stale rows, and confirmed the write over
  // the wrong case's chrome (B5-012 class). The case is carried through the
  // mutation instead.
  const activeCase = useRef(caseId)
  activeCase.current = caseId
  const invalidateTimeline = (forCase: string) =>
    queryClient.invalidateQueries({ queryKey: ['timeline', forCase] })
  const invalidateColumns = (forCase: string) =>
    queryClient.invalidateQueries({ queryKey: ['virtual-columns', forCase] })

  const toggleTagMutation = useMutation({
    mutationFn: (event: TimelineEvent): Promise<string> => {
      const forCase = caseId
      const call = event.is_tagged
        ? deleteTimelineTag(forCase, event.id)
        : createTimelineTag(forCase, event.id)
      return call.then(() => forCase)
    },
    onSuccess: (forCase) => void invalidateTimeline(forCase),
    onError: () => toast.error('Failed to update tag'),
  })

  const noteMutation = useMutation({
    mutationFn: ({ eventId, note }: { eventId: string; note: string }) => {
      const forCase = caseId
      return updateTimelineTag(forCase, eventId, note).then(() => forCase)
    },
    onSuccess: (forCase) => {
      void invalidateTimeline(forCase)
      if (forCase !== activeCase.current) return
      setNoteEvent(null)
      toast.success('Note saved')
    },
    onError: () => toast.error('Failed to save note'),
  })

  const createColumnMutation = useMutation({
    mutationFn: (def: VirtualColumnDef) => {
      const forCase = caseId
      return createVirtualColumn(forCase, def).then((created) => ({
        created,
        forCase,
      }))
    },
    onSuccess: ({ created, forCase }) => {
      void invalidateColumns(forCase)
      if (forCase !== activeCase.current) return
      setVisibleColumnIds([...visibleColumnIds, created.id])
      toast.success('Column created')
    },
    onError: () => toast.error('Failed to create column'),
  })

  const deleteColumnMutation = useMutation({
    mutationFn: (columnId: string) => {
      const forCase = caseId
      return deleteVirtualColumn(forCase, columnId).then(() => forCase)
    },
    onSuccess: (forCase, columnId) => {
      void invalidateColumns(forCase)
      if (forCase !== activeCase.current) return
      setVisibleColumnIds(visibleColumnIds.filter((id) => id !== columnId))
    },
    onError: () => toast.error('Failed to delete column'),
  })

  // ---- Handlers ----
  const handleSort = (field: string) => {
    const nextOrder = sortBy === field && sortOrder === 'desc' ? 'asc' : 'desc'
    // Reset to page 1 like every other filter change: re-sorting reorders the
    // whole result set, so a deep page would otherwise land the examiner on an
    // empty or non-leading slice and read as "no events".
    updateParams({ sort_by: field, sort_order: nextOrder })
  }

  // The body file ends with a `#` verdict comment rather than a CSV or JSON
  // row, so it is checked as the 'body' shape; the PDF and SQLite exports have
  // no text verdict at all (see the comment in `handleExport`).
  const exportTerminatorFor = (format: ExportFormat) => {
    if (format === 'pdf' || format === 'sqlite') return undefined
    if (format === 'body_events') {
      return { marker: '### END OF EXPORT ###', format: 'body' as const }
    }
    return exportTerminator(format)
  }

  const handleExport = async (format: ExportFormat) => {
    setExporting(format)
    try {
      await downloadFile(
        `/cases/${caseId}/timeline/export/${format}`,
        `timeline_${caseId}.${EXPORT_EXTENSION[format]}`,
        {
          query: filterParams,
          // The server streams the CSV and JSON with no Content-Length and
          // ends each with the same verdict row the search export carries, and
          // its own preamble says a file without that row must not be
          // tendered. The search page passed the terminator; this page had not
          // been brought with it, so a timeline export cut short in transit
          // was saved and reported as a success.
          //
          // The PDF and the SQLite database are different documents: laid out
          // (or committed) whole, bounded, and with no text verdict row to
          // look for -- the SQLite file states its own completeness in its
          // `export_meta` table instead, which is not something a byte-stream
          // terminator check can see. Handing the helper a terminator for
          // either made it judge every such export a fragment and refuse to
          // report it as saved (UI-026, the PDF case; the same failure would
          // hit the SQLite export for the same reason).
          terminator: exportTerminatorFor(format),
          unbounded: format !== 'pdf' && format !== 'sqlite',
        },
      )
    } catch {
      toast.error(`Export ${format.toUpperCase()} failed`)
    } finally {
      setExporting(null)
    }
  }

  const data = timelineQuery.data
  // On a search/module/range/sort change the placeholder is the previous
  // filter's response. Its event rows must not render under the new filter
  // chrome (tagging/acting on the wrong set); the rows are replaced with a
  // loading state below while the surrounding chrome stays put. A page change
  // keeps the same filterKey, so paging stays smooth (rows are not gated).
  const staleFilter = data != null && data._filterKey !== filterKey
  const events = data?.events ?? []
  const rawPagination = data?.pagination

  // Cache the real total whenever the server computed one, then reuse it while
  // paging (when the response carries the -1 "not computed" sentinel). Skip
  // placeholder data: on a filter change it is the previous filter's response,
  // and tagging its total with the new filterKey would poison the cache so a
  // later count=false page reuses a total that belongs to the old filter.
  const showingPlaceholder = timelineQuery.isPlaceholderData
  useEffect(() => {
    if (!showingPlaceholder && rawPagination && rawPagination.total_count >= 0) {
      countCacheRef.current = {
        key: filterKey,
        total_count: rawPagination.total_count,
        total_pages: rawPagination.total_pages,
      }
    }
  }, [rawPagination, filterKey, showingPlaceholder])

  // Reuse the cached total only when it was computed for THESE filters. The
  // write path is already keyed; the read path must check the same key or a
  // count from the previous filter set (or previous case) is merged into this
  // response's pagination, mis-stating "N events" and inventing pages that
  // resolve empty (BUG-265).
  const cachedCount =
    countCacheRef.current?.key === filterKey ? countCacheRef.current : null
  const pagination =
    rawPagination && rawPagination.total_count < 0 && cachedCount
      ? {
          ...rawPagination,
          total_count: cachedCount.total_count,
          total_pages: cachedCount.total_pages,
        }
      : rawPagination

  // A placeholder kept from another filter (or another case) carries that
  // result set's total, and "N events" under the new chrome mis-states how much
  // evidence matched. Gate the count the same way the rows are gated; the page
  // controls are gated with it below, since every field they read (page,
  // total_pages) comes from that same placeholder response (BUG-195).
  const shownTotalCount = staleFilter ? undefined : pagination?.total_count

  // Analysis filter trims only the already-loaded page; server totals and
  // pagination are unaffected.
  const analysisFiltered =
    analysisFilter === 'fn'
      ? events.filter(isFnEvent)
      : analysisFilter === 'timestomp'
        ? events.filter((e) => timestompHint(e) !== null)
        : events

  // The quick type-ahead (§1.1), layered under the analysis chips and the
  // server-side filters. This one is the sharpest case for the primitive's
  // disclosure: the timeline is server-paged over a case that can hold
  // millions of events, so a needle here narrows ONE PAGE and its count is a
  // count on that page. `loadedIsSubset` is therefore always true, and the bar
  // says which page-sized population it searched and what a missing event does
  // not mean.
  const pageFilter = useQuickFilter(caseId, analysisFiltered, (e) => [
    e.short_desc,
    e.timestamp_desc,
    e.source_module,
    e.full_details,
  ])
  const visibleEvents = pageFilter.rows

  // Tag or untag every selected event via the per-event endpoint, at most
  // BULK_CONCURRENCY requests in flight, then invalidate the timeline once.
  const runBulk = async (mode: 'tag' | 'untag') => {
    // Bound to the case the bulk run was started in, so a case switch mid-run
    // cannot redirect the writes or the refresh that follows them.
    const forCase = caseId
    const ids = [...selectedIds]
    const total = ids.length
    if (total === 0 || bulkProgress) return
    setBulkProgress({ done: 0, total })
    let done = 0
    let failed = 0
    const queue = [...ids]
    const worker = async () => {
      for (;;) {
        const id = queue.shift()
        if (id === undefined) return
        try {
          if (mode === 'tag') await createTimelineTag(forCase, id)
          else await deleteTimelineTag(forCase, id)
        } catch {
          failed += 1
        }
        done += 1
        setBulkProgress({ done, total })
      }
    }
    await Promise.all(
      Array.from({ length: Math.min(BULK_CONCURRENCY, total) }, worker),
    )
    setBulkProgress(null)
    setSelectedIds(new Set())
    if (failed === 0) {
      toast.success(
        mode === 'tag'
          ? `Tagged ${total} event${total === 1 ? '' : 's'}`
          : `Removed tags from ${total} event${total === 1 ? '' : 's'}`,
      )
    } else {
      toast.error(`${failed} of ${total} events failed to update`)
    }
    void invalidateTimeline(forCase)
  }

  // Depends on the setter, which is memoized per slice: a callback captured
  // once with `[]` would keep writing the PREVIOUS slice's selection, so ticking
  // a checkbox after a case switch would silently do nothing.
  const toggleSelect = useCallback(
    (eventId: string, selected: boolean) => {
      setSelectedIds((prev) => {
        const next = new Set(prev)
        if (selected) next.add(eventId)
        else next.delete(eventId)
        return next
      })
    },
    [setSelectedIds],
  )

  return (
    <div>
      <div className="tl-title-row">
        <h1 className="page-title">Timeline</h1>
        <SavedViewsMenu
          storageKey={`seance.views.timeline.${caseId}`}
          currentQuery={searchParams.toString()}
          onApply={(query) => setSearchParams(new URLSearchParams(query))}
        />
      </div>
      <TimelineToolbar
        caseId={caseId}
        filters={{
          search,
          range,
          from,
          to,
          modules,
          taggedOnly,
          pageSize,
        }}
        moduleCounts={modulesQuery.data}
        totalCount={shownTotalCount}
        exporting={exporting}
        analysisFilter={analysisFilter}
        onChange={updateParams}
        onExport={handleExport}
        onOpenColumns={() => setColumnsModalOpen(true)}
        onAnalysisFilterChange={setAnalysisFilter}
      />

      <div className="tl-chart">
        <div
          className="tl-chart-toggle"
          role="group"
          aria-label="Timeline chart view"
        >
          <button
            className={chartView === 'activity' ? 'active' : ''}
            aria-pressed={chartView === 'activity'}
            onClick={() => updateParams({ chart: null }, false)}
          >
            Activity
          </button>
          <button
            className={chartView === 'swimlanes' ? 'active' : ''}
            aria-pressed={chartView === 'swimlanes'}
            onClick={() => updateParams({ chart: 'swimlanes' }, false)}
          >
            Swimlanes
          </button>
          <button
            className={chartView === 'heatmap' ? 'active' : ''}
            aria-pressed={chartView === 'heatmap'}
            onClick={() => updateParams({ chart: 'heatmap' }, false)}
          >
            Heatmap
          </button>
        </div>
        {chartView === 'activity' && (
          <ActivityHistogram
            data={staleHistogram ? undefined : histogramQuery.data}
            isError={histogramQuery.isError}
            error={histogramQuery.error}
            hasRange={from !== null || to !== null}
            onBrush={(brushFrom, brushTo) =>
              updateParams({
                from: String(brushFrom),
                to: String(brushTo),
                range: null,
              })
            }
            onClearRange={() => updateParams({ from: null, to: null })}
          />
        )}
        {chartView === 'swimlanes' && (
          <TimelineSwimlanes
            data={staleSwimlanes ? undefined : swimlanesQuery.data}
            isError={swimlanesQuery.isError}
            hasRange={from !== null || to !== null}
            onBrush={(brushFrom, brushTo) =>
              updateParams({
                from: String(brushFrom),
                to: String(brushTo),
                range: null,
              })
            }
            onClearRange={() => updateParams({ from: null, to: null })}
          />
        )}
        {chartView === 'heatmap' &&
          (activityQuery.isError ? (
            <div className="error-note">Could not load activity heatmap.</div>
          ) : (
            <ActivityHeatmap data={activityQuery.data} />
          ))}
      </div>

      {selectedIds.size > 0 && (
        <div className="tl-bulk-bar">
          <span className="tl-bulk-count">{selectedIds.size} selected</span>
          {bulkProgress && (
            <span className="mono tl-bulk-progress">
              {bulkProgress.done}/{bulkProgress.total}…
            </span>
          )}
          <button
            className="btn"
            disabled={bulkProgress !== null}
            onClick={() => runBulk('tag')}
          >
            Tag {selectedIds.size}
          </button>
          <button
            className="btn"
            disabled={bulkProgress !== null}
            onClick={() => runBulk('untag')}
          >
            Untag {selectedIds.size}
          </button>
          <button
            className="link-button"
            disabled={bulkProgress !== null}
            onClick={() => setSelectedIds(new Set())}
          >
            Clear selection
          </button>
        </div>
      )}

      {timelineQuery.isPending ? (
        <SkeletonTable rows={10} cols={5} label="Loading timeline" />
      ) : timelineQuery.isError ? (
        <div className="error-note">
          Failed to load timeline: {timelineQuery.error.message}
        </div>
      ) : events.length === 0 && !staleFilter ? (
        // Only claim "no events" for the result set actually on screen: an
        // empty placeholder from another filter/case must read as loading, not
        // as an empty case (BUG-195).
        <div className="empty-state">
          <h3>No timeline events</h3>
          <p>
            No events match the current filters. Adjust the filters or ingest
            evidence to populate the timeline.
          </p>
        </div>
      ) : (
        <>
          {analysisFilter !== 'all' && !staleFilter && (
            <div className="tl-loaded-note">
              Analysis filter active — showing {visibleEvents.length} of{' '}
              {events.length} events loaded on this page.
            </div>
          )}
          {/* Which window narrowed this page, in the page's own words. The
              persistent bar names the case-wide one; this says whether the
              page is under it or under a brush of its own, because the two
              look identical once the rows are drawn (§1.1). */}
          {!localWindow && caseWindow != null && (
            <div className="tl-loaded-note" data-testid="tl-case-window">
              Narrowed by the case-wide time window in the bar above. The
              counts and pages below are inside that window, not across the
              case; brushing the chart on this page replaces it for this page.
            </div>
          )}
          {!staleFilter && (
            <QuickFilterBar
              filter={pageFilter}
              noun="event"
              placeholder="Filter the events on this page…"
              // Always: the timeline is server-paged, so this box never
              // searches more than one page of a case that may hold millions.
              loadedIsSubset
              total={shownTotalCount}
            />
          )}
          {staleFilter ? (
            <SkeletonTable rows={10} cols={5} label="Loading timeline" />
          ) : visibleEvents.length === 0 ? (
            <div className="empty-state">
              <h3>No matching events</h3>
              <p>
                No events on the loaded page match the filters set here. Clear
                them or move to another page — the case's own total is
                unaffected by either.
              </p>
            </div>
          ) : (
            <EventsTable
              events={visibleEvents}
              caseId={caseId}
              columns={visibleColumns}
              sortBy={sortBy}
              sortOrder={sortOrder}
              selectedIds={selectedIds}
              onSort={handleSort}
              onToggleTag={toggleTagMutation.mutate}
              onEditNote={setNoteEvent}
              onToggleSelect={toggleSelect}
              onToggleSelectAll={(selected) =>
                setSelectedIds(
                  selected ? new Set(visibleEvents.map((e) => e.id)) : new Set(),
                )
              }
            />
          )}
          {/* Withdrawn while the rows are, and for the same reason: `page` and
              `total_pages` are the placeholder's, i.e. the previous filter's.
              Left live, Next/Last compute their target from a total that no
              longer applies and land the examiner on a page the new filter does
              not have, which then renders as "No timeline events" -- a filter
              artefact that reads as a finding about the evidence. */}
          {pagination && !staleFilter && (
            <Pager
              page={pagination.page}
              totalPages={pagination.total_pages}
              totalCount={shownTotalCount}
              onPage={(p) =>
                updateParams({ page: p <= 1 ? null : String(p) }, false)
              }
            />
          )}
        </>
      )}

      {columnsModalOpen && (
        <ColumnSettingsModal
          columns={virtualColumns}
          visibleIds={visibleColumnIds}
          creating={createColumnMutation.isPending}
          onToggle={(id, visible) =>
            setVisibleColumnIds(
              visible
                ? [...visibleColumnIds, id]
                : visibleColumnIds.filter((v) => v !== id),
            )
          }
          onCreate={(name, paths) =>
            createColumnMutation.mutate({
              id: slugId(name),
              name,
              description: '',
              type: 'string',
              sources: paths.map((path) => ({ path, artifact_types: [] })),
              default_visible: true,
              built_in: false,
            })
          }
          onDelete={(id) => deleteColumnMutation.mutate(id)}
          onClose={() => setColumnsModalOpen(false)}
        />
      )}

      {noteEvent && (
        <TagNoteModal
          event={noteEvent}
          saving={noteMutation.isPending}
          onSave={(note) => noteMutation.mutate({ eventId: noteEvent.id, note })}
          onClose={() => setNoteEvent(null)}
        />
      )}
    </div>
  )
}
