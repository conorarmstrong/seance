import {
  keepPreviousData,
  useMutation,
  useQuery,
} from '@tanstack/react-query'
import { Folder } from 'lucide-react'
import { iconForName } from '../../lib/fileIcon'
import { Fragment, useEffect, useRef, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { IncompleteBadge } from '../../components/Incompleteness'
import { ContextMenu } from '../../components/ContextMenu'
import { Pager } from '../../components/Pager'
import { SkeletonTable } from '../../components/Skeleton'
import { useToast } from '../../components/toast/ToastProvider'
import { DownloadIncompleteError, downloadFile } from '../../lib/download'
import { formatBytes, formatCount, formatUtc } from '../../lib/format'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { useRovingRows } from '../../hooks/useRovingRows'
import { exportFilesZip, listFiles } from './api'
import { DetailPane } from './DetailPane'
import { DirTree } from './DirTree'
import { FileTree } from './FileTree'
import type {
  FileRow,
  FileSortKey,
  FilterPopulationDisclosure,
  KnownFilter,
  SortOrder,
} from './types'
import './files.css'

const KNOWN_OPTIONS: { value: '' | KnownFilter; label: string }[] = [
  { value: '', label: 'All files' },
  { value: 'notable', label: 'Notable only' },
  { value: 'known', label: 'Known-good only' },
  { value: 'unknown', label: 'Unknown only' },
]

const SORTABLE: { key: FileSortKey; label: string }[] = [
  { key: 'name', label: 'Name' },
  { key: 'size', label: 'Size' },
  { key: 'modified', label: 'Modified' },
  { key: 'created', label: 'Created' },
]

const PAGE_SIZES = [100, 250, 500]

/**
 * How long a folder path may get before the breadcrumb starts collapsing, and
 * how many trailing folders it keeps when it does.
 *
 * Users/john/AppData/Local/Packages/Microsoft.WindowsStore_8wekyb3d8bbwe/…
 * is a routine Windows depth, and rendering every segment wrapped the crumb
 * over three lines, pushing the grid and its count bar down the page — and it
 * grew with every click deeper. Root plus the first folder says which volume
 * and which top-level tree; the last three say where the examiner is standing.
 * The middle is the part of a 200-character path nobody reads, so it collapses
 * behind a control that still lists and still navigates.
 */
const CRUMB_MAX_SEGMENTS = 5
const CRUMB_TAIL_SEGMENTS = 3

/** The empty row selection, as one shared value so that scoping the selection
 * back to "nothing selected" returns a stable reference. Never mutated. */
const NO_SELECTION: string[] = []

function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(timer)
  }, [value, delayMs])
  return debounced
}

function DirIcon() {
  return <Folder size={15} className="fg-glyph fg-glyph-dir" aria-label="Directory" />
}

function FileIcon({ name }: { name?: string }) {
  const Icon = iconForName(name)
  return <Icon size={15} className="fg-glyph fg-glyph-file" aria-label="File" />
}

function pathSegments(path: string): string[] {
  return path.split('/').filter(Boolean)
}

/** Hash-set triage badge. Notable is a known-bad hit (high signal); known
 * is a known-good hit (e.g. NSRL) and de-prioritised. Null renders nothing. */
function KnownBadge({ status }: { status: FileRow['known_status'] }) {
  if (status === 'notable') {
    return (
      <span
        className="badge fg-badge-notable"
        title="Hash-set hit on a NOTABLE / known-bad set. High signal: review this file."
      >
        Notable
      </span>
    )
  }
  if (status === 'known') {
    return (
      <span
        className="badge fg-badge-known"
        title="Hash-set hit on a known-good set (e.g. NSRL). Safe to de-prioritise."
      >
        Known
      </span>
    )
  }
  return null
}

/**
 * What a saved compound filter did to this grid, said out loud.
 *
 * A grid narrowed by a filter looks exactly like a grid of a small case, and
 * the difference between those two readings is the difference between "the
 * evidence holds four of these" and "four of these matched". So the filter is
 * named, both its numbers are shown, and every way the population can be short
 * is carried through from the server rather than being flattened into the row
 * count — in the same words, and against the same closed vocabulary, that the
 * filters page uses for the same facts.
 */
function FilterPopulationBar({
  filter,
  onClear,
}: {
  filter: FilterPopulationDisclosure
  onClear: () => void
}) {
  const matched = formatCount(filter.matched)
  return (
    <div
      className="fg-filter-bar"
      data-testid="fg-filter-bar"
      // The server's own token for the shortfall, carried verbatim so that a
      // reader (or a screenshot) can be matched against the filters page's
      // disclosure for the same filter. Null when there is no shortfall.
      data-incomplete-reason={filter.inventory_incomplete_reason ?? undefined}
    >
      <div className="fg-filter-head">
        <span className="fg-filter-name">
          Showing the population of filter{' '}
          <strong>{filter.filter_name}</strong>
        </span>
        <span className="fg-filter-counts">
          {matched} matched · {formatCount(filter.listed)} listed here
        </span>
        <button type="button" className="btn btn-sm" onClick={onClear}>
          Clear filter
        </button>
      </div>

      {/* The two numbers legitimately differ, and the gap is not rows going
          missing. Saying so is what stops "9 matched, 4 listed" being read as
          five rows this grid lost. */}
      {filter.matched !== filter.listed && (
        <p className="fg-filter-note" data-testid="fg-filter-gap">
          The filter is evaluated over every artifact type in the whole case;
          this grid lists file-system entries under this evidence source, and
          the grid&apos;s own filters narrow it further. Matches of other
          artifact types, and files under other evidence sources, are not rows
          here.
        </p>
      )}

      {/* The case-wide scan stops at a row ceiling. When it did, the match
          count is a floor and an absence below is not evidence of absence —
          the same fact the filters page states in the same words (B6-008). */}
      {!filter.scan_complete && (
        <div
          className="warn-note"
          role="note"
          data-testid="fg-filter-scan-incomplete"
        >
          The scan stopped at the case-wide row ceiling before reaching the end
          of this case. {matched} is the number of matches found so far, not
          the number that exist — artifacts this filter would match were never
          examined, so rows missing from this grid are not established
          absences.
        </div>
      )}

      {/* A scan that ran to the end and could not read some rows is short in a
          way paging cannot repair, and `scan_complete` is true for it
          (B8-028). */}
      {filter.undecodable > 0 && (
        <div
          className="warn-note"
          role="note"
          data-testid="fg-filter-undecodable"
        >
          {formatCount(filter.undecodable)} artifact
          {filter.undecodable === 1 ? '' : 's'} could not be read while this
          filter ran, so {matched} is a floor. They may or may not have
          matched; the scan reached them and could not say.
        </div>
      )}

      {/* More matches than the grid will carry. Unlike the two above, paging
          through this grid will not reach them at all: the population handed
          to the listing was cut at the ceiling. */}
      {filter.population_capped && (
        <div
          className="warn-note"
          role="note"
          data-testid="fg-filter-population-capped"
        >
          This filter matched more artifacts than the grid will list — the
          ceiling is {formatCount(filter.population_cap)}. Rows past it were
          never handed to this listing, so paging cannot reach them; narrow the
          filter to see the rest.
        </div>
      )}
    </div>
  )
}

/** Carved detection: is_carved was removed from rows; fall back to the
 * carver's name prefix. Rows now always carry metadata (hashes), so the
 * signal is the name, not metadata presence. */
function isCarved(row: FileRow): boolean {
  return !row.is_directory && row.name.startsWith('carved_')
}

function csvField(value: string): string {
  if (/[",\n]/.test(value)) return `"${value.replace(/"/g, '""')}"`
  return value
}

function buildCsv(rows: FileRow[]): string {
  const header = [
    'name',
    'path',
    'extension',
    'size',
    'created',
    'modified',
    'accessed',
    'kind',
    'deleted',
  ]
  const lines = rows.map((row) =>
    [
      row.name,
      row.path,
      row.extension ?? '',
      row.size != null ? String(row.size) : '',
      row.created ?? '',
      row.modified ?? '',
      row.accessed ?? '',
      row.is_directory ? 'directory' : 'file',
      String(row.is_deleted),
    ]
      .map(csvField)
      .join(','),
  )
  return [header.join(','), ...lines].join('\n')
}

function downloadCsv(csv: string, filename: string) {
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  // Defer revocation: revoking synchronously right after click() can abort the
  // download before the browser reads the blob, yielding an empty CSV on some
  // browsers (BUG-169).
  setTimeout(() => URL.revokeObjectURL(url), 60_000)
}

/** The server's end-of-export marker (`seance_reporting::body_file`). */
const BODY_FILE_MARKER = '### END OF EXPORT ###'

export function FileGridPage() {
  const { caseId = '', sourceId = '' } = useParams()
  const navigate = useNavigate()
  const toast = useToast()
  const [searchParams, setSearchParams] = useSearchParams()

  const viewParam = searchParams.get('view')
  const view: 'folder' | 'flat' | 'tree' =
    viewParam === 'flat' ? 'flat' : viewParam === 'tree' ? 'tree' : 'folder'
  const dir = searchParams.get('dir')
  // Coerce defensively: a malformed URL (?page=abc) must not send NaN to the API.
  const page = Math.max(1, Number(searchParams.get('page') ?? '1') || 1)
  const pageSize = Number(searchParams.get('page_size') ?? '100') || 100
  const deletedOnly = searchParams.get('deleted') === 'true'
  const uniqueOnly = searchParams.get('unique') === 'true'
  const knownParam = searchParams.get('known')
  const known: KnownFilter | '' =
    knownParam === 'notable' || knownParam === 'known' || knownParam === 'unknown'
      ? knownParam
      : ''
  const nameContains = searchParams.get('name_contains') ?? ''
  const extension = searchParams.get('extension') ?? ''
  // A saved compound filter whose population the grid is showing. It rides in
  // the URL like every other view parameter, so the filtered grid is a link an
  // examiner can bookmark, hand over, or reload.
  const filterId = searchParams.get('filter_id') ?? ''
  const sortBy = (searchParams.get('sort_by') as FileSortKey | null) ?? 'name'
  const sortOrder: SortOrder =
    searchParams.get('sort_order') === 'desc' ? 'desc' : 'asc'

  // Folder navigation is path-based: `dir` holds a directory path (e.g.
  // "/etc"), or is absent at the filesystem root. Breadcrumbs derive purely
  // from that path, so deep links need no id recovery.
  const anchorId = useRef<string | null>(null)
  // Where to draw the menu of collapsed breadcrumb segments, or null when it
  // is closed.
  const [crumbMenu, setCrumbMenu] = useState<{ x: number; y: number } | null>(
    null,
  )

  function setParams(patch: Record<string, string | null>) {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev)
        for (const [key, value] of Object.entries(patch)) {
          if (value === null || value === '') next.delete(key)
          else next.set(key, value)
        }
        return next
      },
      { replace: true },
    )
  }

  function clearSelection() {
    setSelectedIds([])
    anchorId.current = null
  }

  // Debounced text filters; committing a filter resets to page 1.
  //
  // The typed text belongs to one case + evidence source. Holding it in plain
  // state let a switch land text typed against source A into source B's URL:
  // the sync effects below only fire when the URL value changes, and a case or
  // source change usually leaves both filters empty, so nothing reset the box
  // and the still-pending debounce wrote case A's filter onto case B's file
  // list (B2-020). Scoping the text to `caseId/sourceId` blanks it back to the
  // new URL's value DURING the switching render, which also restarts the
  // debounce, so the pending value is dropped rather than committed.
  const filterScope = `${caseId}/${sourceId}`
  const [nameInput, setNameInput] = useEntityScopedState(
    filterScope,
    nameContains,
  )
  // Sync the input when the URL changes externally (back/forward, saved views).
  // Resetting the input also restarts the debounce, so a filter navigation can't
  // be clobbered by a pending debounce re-pushing the stale typed value.
  useEffect(() => {
    setNameInput(nameContains)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nameContains])
  const debouncedName = useDebounced(nameInput, 300)
  useEffect(() => {
    if (debouncedName !== nameContains) {
      setParams({ name_contains: debouncedName, page: null })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedName])

  const [extInput, setExtInput] = useEntityScopedState(filterScope, extension)
  useEffect(() => {
    setExtInput(extension)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [extension])
  const debouncedExt = useDebounced(extInput, 300)
  useEffect(() => {
    if (debouncedExt !== extension) {
      setParams({ extension: debouncedExt, page: null })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedExt])

  // Identity of the current folder/filter view (page excluded, so paging within
  // one view stays smooth). Each response is tagged with it so a placeholder
  // left over from a different folder/filter can be told apart and gated out.
  // caseId and sourceId are part of the identity: switching evidence source or
  // case with the same path/filters/sort would otherwise leave the tag matching
  // and render the previous filesystem's rows under the new source/case chrome
  // (BUG-196) -- the folder-change window is already guarded by `dir` (BUG-111).
  const gridKey = JSON.stringify({
    caseId,
    sourceId,
    view,
    dir,
    filterId,
    pageSize,
    deletedOnly,
    uniqueOnly,
    known,
    nameContains,
    extension,
    sortBy,
    sortOrder,
  })

  const grid = useQuery({
    queryKey: [
      'files',
      caseId,
      sourceId,
      {
        view,
        dir,
        filterId,
        page,
        pageSize,
        deletedOnly,
    uniqueOnly,
        known,
        nameContains,
        extension,
        sortBy,
        sortOrder,
      },
    ],
    queryFn: async () => ({
      ...(await listFiles(caseId, sourceId, {
        // Folder mode lists one path level (empty = filesystem root); flat mode
        // lists the whole subtree. The tree is derived from the path column,
        // since files are stored flat under the FileSystem artifact.
        path: view === 'folder' ? (dir ?? '') : undefined,
        filter_id: filterId || undefined,
        name: nameContains || undefined,
        extension: extension || undefined,
        deleted_only: deletedOnly || undefined,
        unique_only: uniqueOnly || undefined,
        known: known || undefined,
        sort: sortBy,
        order: sortOrder,
        page,
        page_size: pageSize,
        include_metadata: true,
      })),
      _key: gridKey,
    }),
    enabled: caseId !== '' && sourceId !== '' && view !== 'tree',
    placeholderData: keepPreviousData,
  })

  // keepPreviousData keeps the prior rows while the next page loads (smooth
  // paging), but on a folder/filter change the placeholder is the previous
  // folder's rows — which would render under the new breadcrumb, letting the
  // examiner open or export the wrong files. Gate on the identity tag so stale
  // rows read as still-loading (mirrors the BUG-068 Hex/Text/Registry fix).
  const staleGrid = grid.data != null && grid.data._key !== gridKey
  const items = staleGrid ? [] : (grid.data?.items ?? [])

  // Breadcrumb segments derived from the current dir path. The cumulative path
  // up to segment i is what clicking that crumb navigates to.
  const dirSegments = dir ? pathSegments(dir) : []
  const crumbPath = (index: number) =>
    '/' + dirSegments.slice(0, index + 1).join('/')

  // Each crumb carries its index into `dirSegments`, because once the middle
  // is collapsed a crumb's position on screen no longer tells you what path it
  // stands for — and a breadcrumb that navigates to the wrong folder is worse
  // than one that wraps.
  const numberedSegments = dirSegments.map((name, index) => ({ name, index }))
  const crumbsCollapse = dirSegments.length > CRUMB_MAX_SEGMENTS
  const hiddenCrumbs = crumbsCollapse
    ? numberedSegments.slice(1, dirSegments.length - CRUMB_TAIL_SEGMENTS)
    : []
  const shownCrumbs = crumbsCollapse
    ? [
        numberedSegments[0],
        ...numberedSegments.slice(dirSegments.length - CRUMB_TAIL_SEGMENTS),
      ]
    : numberedSegments

  // Selection is scoped to the exact rows on screen: the whole grid identity
  // plus the page. Anything that can change the row set — case, source, view,
  // directory, page, page size, every server-side filter, the sort — takes the
  // selection with it, so a "N selected" count (and the ZIP export built from
  // it) can never carry ids for rows the tightened filter has hidden (export of
  // invisible evidence), nor case A's artifact ids into case B's export
  // endpoint (BUG-263).
  //
  // Clearing this from a `useEffect` left one committed frame in which the
  // toolbar said "12 selected" over case B's file list while `selectedIds` held
  // case A's ids; "Export ZIP" pressed on that frame POSTs them to case B.
  // Resolving the selection against the current grid during render means the
  // frame never exists (B2-149).
  const selectionScope = `${gridKey}|${page}`
  const [selectedIds, setSelectedIds] = useEntityScopedState<string[]>(
    selectionScope,
    NO_SELECTION,
  )

  // The tree view's single-node selection is a whole FileRow belonging to one
  // case and evidence source; its detail pane and "open" action would otherwise
  // resolve case A's artifact id against case B (BUG-263).
  const [treeSelected, setTreeSelected] = useEntityScopedState<FileRow | null>(
    filterScope,
    null,
  )

  // Navigate to a directory path (null / empty = filesystem root).
  function goToDir(path: string | null) {
    clearSelection()
    setParams({ dir: path, page: null })
  }

  function descend(row: FileRow) {
    goToDir(row.path)
  }

  function setView(next: 'folder' | 'flat' | 'tree') {
    if (next === view) return
    clearSelection()
    setTreeSelected(null)
    setParams({
      view: next === 'folder' ? null : next,
      dir: null,
      page: null,
    })
  }

  function onSort(column: FileSortKey) {
    if (sortBy === column) {
      setParams({
        sort_order: sortOrder === 'asc' ? 'desc' : 'asc',
        page: null,
      })
    } else {
      setParams({ sort_by: column, sort_order: 'asc', page: null })
    }
  }

  function openArtifact(id: string) {
    navigate(`/cases/${caseId}/artifacts/${id}`)
  }

  function activate(row: FileRow) {
    if (view === 'folder' && row.is_directory) descend(row)
    else openArtifact(row.id)
  }

  function onRowClick(event: React.MouseEvent, row: FileRow) {
    // No focus() here: the click focuses the <tr> itself, which is the
    // table's roving tab stop, and useRovingRows adopts it as the active row.
    if (event.shiftKey && anchorId.current) {
      const from = items.findIndex((i) => i.id === anchorId.current)
      const to = items.findIndex((i) => i.id === row.id)
      if (from !== -1 && to !== -1) {
        const [lo, hi] = from <= to ? [from, to] : [to, from]
        setSelectedIds(items.slice(lo, hi + 1).map((i) => i.id))
        return
      }
    }
    if (event.metaKey || event.ctrlKey) {
      setSelectedIds((prev) =>
        prev.includes(row.id)
          ? prev.filter((id) => id !== row.id)
          : [...prev, row.id],
      )
      anchorId.current = row.id
      return
    }
    setSelectedIds([row.id])
    anchorId.current = row.id
  }

  // Keyboard navigation for the grid, on the shared roving-tabindex primitive
  // rather than a per-page one: the whole table is a single tab stop, the
  // arrows move real DOM focus (so a screen reader reads out the row arrived
  // at, which repainting a highlight cannot do), and the hook scrolls the new
  // row into view — with page_size up to 500 the selection otherwise walks
  // off the bottom of the container and the examiner loses count.
  //
  // `onMove` fires only for keyboard moves, never for the focus a click also
  // causes, so ctrl-click and shift-click selections survive being clicked on.
  const roving = useRovingRows({
    count: items.length,
    onMove: (index) => {
      const row = items[index]
      if (!row) return
      setSelectedIds([row.id])
      anchorId.current = row.id
    },
    onActivate: (index) => {
      const row = items[index]
      if (row) activate(row)
    },
  })

  // The whole case as a Sleuth Kit body file (`GET …/timeline/export/body`).
  // The route is case-wide and takes no filters — a body file filtered to what
  // is on screen would be a file list with files missing and nothing on its
  // face to say so — so the control says both, beside the button, rather than
  // sitting among controls that do honour this page's source and filters.
  // Its own preamble and verdict line say the same inside the file.
  const [bodyExporting, setBodyExporting] = useState(false)
  const [bodyExportError, setBodyExportError] = useEntityScopedState<
    string | null
  >(caseId, null)
  // What happened to a body file that arrived whole: saved (with the verdict
  // the file itself states) or cancelled. A whole file can still say it is
  // INCOMPLETE — the FileEntry set changed while the walk ran, or the walk
  // stopped early — and that goes to the error note, never to this one.
  const [bodyExportStatus, setBodyExportStatus] = useEntityScopedState<
    string | null
  >(caseId, null)

  async function exportCaseBodyFile() {
    if (!caseId) return
    setBodyExporting(true)
    setBodyExportError(null)
    setBodyExportStatus(null)
    try {
      const outcome = await downloadFile(
        `/cases/${caseId}/timeline/export/body`,
        `body_${caseId}.txt`,
        {
          // One row per FileEntry in the case: no ceiling, so stream to a
          // chosen file where the browser allows, and check the verdict line
          // the server ends every whole file with.
          unbounded: true,
          terminator: { marker: BODY_FILE_MARKER, format: 'body' },
        },
      )
      if (outcome.cancelled) {
        setBodyExportStatus(
          'Body file export cancelled: nothing was written.',
        )
      } else if (!outcome.verdict || !/^VERDICT: COMPLETE\b/.test(outcome.verdict)) {
        // Whole, but the file's own verdict says it is not the whole case
        // (or states no verdict this page can read). Not a saved export.
        setBodyExportError(
          `The body file (${formatBytes(outcome.bytes)}) was written, but its own last line says it is not the complete file list: ${outcome.verdict ?? 'no verdict could be read'}. Click Export whole case as mactime body file to export again.`,
        )
      } else {
        setBodyExportStatus(
          `Body file saved (${formatBytes(outcome.bytes)}). Its last line reads: ${outcome.verdict}`,
        )
      }
    } catch (err) {
      setBodyExportError(
        err instanceof DownloadIncompleteError
          ? err.message
          : `Body file export failed${err instanceof Error && err.message ? `: ${err.message}` : ''}. Click Export whole case as mactime body file to retry.`,
      )
    } finally {
      setBodyExporting(false)
    }
  }

  function exportSelectionCsv() {
    const rows = items.filter((i) => selectedIds.includes(i.id))
    if (rows.length === 0) return
    downloadCsv(buildCsv(rows), 'files-selection.csv')
  }

  const exportZip = useMutation({
    mutationFn: (ids: string[]) => exportFilesZip(caseId, ids),
    onSuccess: (result) => {
      const base = `Exported ${result.fileCount} files, ${result.skippedCount} skipped`
      // The ZIP that leaves this screen is what goes into evidence. The server
      // counts files whose content came up short and files longer than their
      // declared size, and reporting only the file/skipped pair presented an
      // export holding truncated content as a clean one.
      const flags: string[] = []
      if (result.incompleteCount != null && result.incompleteCount > 0) {
        flags.push(
          `${result.incompleteCount} exported with INCOMPLETE content (fewer bytes than the file declares)`,
        )
      }
      if (result.sizeMismatchCount != null && result.sizeMismatchCount > 0) {
        flags.push(
          `${result.sizeMismatchCount} whose size does not match the declared size`,
        )
      }
      if (flags.length > 0) {
        // `error` is the only emphatic tone this toast API has. The export did
        // produce a ZIP; the wording says so, and says what is wrong with it.
        toast.error(
          `${base}. ${flags.join('; ')}. See manifest.json in the ZIP for the affected files before relying on this export.`,
        )
        return
      }
      toast.success(base)
    },
    onError: (error: Error) => toast.error(`Export failed: ${error.message}`),
  })

  const selectedItem =
    selectedIds.length === 1
      ? items.find((item) => item.id === selectedIds[0])
      : undefined

  const isRefetching = grid.isFetching && !grid.isPending
  const flat = view === 'flat'
  const tree = view === 'tree'

  const table = grid.isPending || staleGrid ? (
    <SkeletonTable rows={12} cols={flat ? 8 : 7} label="Loading files" />
  ) : grid.isError ? (
    <div className="error-note">Failed to load files: {grid.error.message}</div>
  ) : items.length === 0 ? (
    <div className="empty-state">
      <h3>{flat ? 'No files match' : 'Empty folder'}</h3>
      <p>
        {flat
          ? 'Adjust the filters to see file system entries.'
          : 'This folder has no entries matching the current filters.'}
      </p>
    </div>
  ) : (
    <>
      <div className="fg-table-wrap" role="group" aria-label="File list">
        <table className="data-table">
          <thead>
            <tr>
              <th aria-label="Kind" />
              {SORTABLE.slice(0, 1).map(({ key, label }) => (
                <th
                  key={key}
                  aria-sort={
                    sortBy === key
                      ? sortOrder === 'asc'
                        ? 'ascending'
                        : 'descending'
                      : undefined
                  }
                >
                  <button
                    type="button"
                    className="fg-sort"
                    disabled={grid.isFetching}
                    onClick={() => onSort(key)}
                  >
                    {label}
                    {sortBy === key && (
                      <span className="fg-sort-arrow">
                        {sortOrder === 'asc' ? '▲' : '▼'}
                      </span>
                    )}
                  </button>
                </th>
              ))}
              {flat && <th>Path</th>}
              <th>Extension</th>
              {SORTABLE.slice(1).map(({ key, label }) => (
                <th
                  key={key}
                  // Only the size column holds a magnitude; the date columns
                  // beside it read left-to-right like the text they are.
                  className={key === 'size' ? 'num' : undefined}
                  aria-sort={
                    sortBy === key
                      ? sortOrder === 'asc'
                        ? 'ascending'
                        : 'descending'
                      : undefined
                  }
                >
                  <button
                    type="button"
                    className="fg-sort"
                    disabled={grid.isFetching}
                    onClick={() => onSort(key)}
                  >
                    {label}
                    {sortBy === key && (
                      <span className="fg-sort-arrow">
                        {sortOrder === 'asc' ? '▲' : '▼'}
                      </span>
                    )}
                  </button>
                </th>
              ))}
              <th>Accessed</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody className="fg-rows">
            {items.map((item, index) => (
              <tr
                key={item.id}
                {...roving.getRowProps(index)}
                className={
                  selectedIds.includes(item.id) ? 'selected' : undefined
                }
                onClick={(event) => onRowClick(event, item)}
                onDoubleClick={() => activate(item)}
              >
                <td className="fg-icon-cell">
                  {item.is_directory ? <DirIcon /> : <FileIcon name={item.name} />}
                </td>
                <td>
                  <span
                    className={
                      item.is_deleted ? 'fg-name fg-name-deleted' : 'fg-name'
                    }
                  >
                    {item.name}
                  </span>
                </td>
                {flat && (
                  <td className="mono fg-path-cell" title={item.path}>
                    {item.path}
                  </td>
                )}
                <td className="mono">{item.extension ?? '—'}</td>
                <td className="mono num">
                  {item.is_directory ? '—' : formatBytes(item.size)}
                </td>
                <td className="mono">{formatUtc(item.modified)}</td>
                <td className="mono">{formatUtc(item.created)}</td>
                <td className="mono">{formatUtc(item.accessed)}</td>
                <td>
                  <span className="fg-badges">
                    {item.is_deleted ? (
                      <span className="badge badge-danger">Deleted</span>
                    ) : isCarved(item) ? (
                      <span className="badge badge-accent">Carved</span>
                    ) : (
                      <span className="badge badge-ok">OK</span>
                    )}
                    <KnownBadge status={item.known_status} />
                    {/* The "OK" badge above is about deletion state, not about
                        whether the bytes are all there. A file the filesystem
                        parser could only partly reconstruct would otherwise sit
                        in this grid marked OK. */}
                    <IncompleteBadge metadata={item.metadata} />
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* `totalIsFloor` is the same expression the count bar above the table
          reads, deliberately the same decision rather than a second one: the
          two say the same number about the same set a page-height apart, and a
          screen that qualifies one and not the other impeaches itself. */}
      <Pager
        page={grid.data.page}
        totalPages={grid.data.total_pages}
        totalCount={grid.data.total_count}
        totalIsFloor={grid.data.filter?.inventory_incomplete ?? false}
        onPage={(next) => setParams({ page: String(next) })}
      />

      {selectedIds.length > 1 && (
        <div className="fg-actions" role="toolbar" aria-label="Selection actions">
          <span className="fg-actions-count">
            {selectedIds.length} selected
          </span>
          <button type="button" className="btn" onClick={exportSelectionCsv}>
            Export CSV of selection
          </button>
          <button
            type="button"
            className="btn"
            disabled={exportZip.isPending}
            onClick={() => exportZip.mutate(selectedIds)}
          >
            {exportZip.isPending
              ? `Exporting ${selectedIds.length} files…`
              : 'Export selected (ZIP + hashes)'}
          </button>
          <button type="button" className="btn" onClick={clearSelection}>
            Clear selection
          </button>
        </div>
      )}

      {selectedItem && (
        <DetailPane
          caseId={caseId}
          item={selectedItem}
          onOpen={() => openArtifact(selectedItem.id)}
        />
      )}
    </>
  )

  return (
    <div className="fg-page">
      <h1 className="page-title">File System</h1>

      <div className="fg-case-export">
        <button
          type="button"
          className="btn"
          disabled={bodyExporting || !caseId}
          aria-describedby="fg-case-export-note"
          onClick={() => void exportCaseBodyFile()}
        >
          {bodyExporting
            ? 'Exporting whole case as mactime body file…'
            : 'Export whole case as mactime body file'}
        </button>
        <span id="fg-case-export-note" className="fg-case-export-note">
          Every file in the case, from every source — not only this one — and
          it ignores the filters below. One line per file with its own MAC
          times, for mactime, log2timeline or Timesketch.
        </span>
        {bodyExportError && (
          <div className="error-note" role="alert">
            {bodyExportError}
          </div>
        )}
        {bodyExportStatus && (
          <div
            className="fg-case-export-status"
            role="status"
            data-testid="fg-case-export-status"
          >
            {bodyExportStatus}
          </div>
        )}
      </div>

      <div className="fg-toolbar">
        <div className="fg-viewtoggle" role="group" aria-label="View mode">
          <button
            type="button"
            className={
              view === 'folder' ? 'btn fg-view-btn active' : 'btn fg-view-btn'
            }
            aria-pressed={view === 'folder'}
            onClick={() => setView('folder')}
          >
            Folders
          </button>
          <button
            type="button"
            className={flat ? 'btn fg-view-btn active' : 'btn fg-view-btn'}
            aria-pressed={flat}
            onClick={() => setView('flat')}
          >
            All files
          </button>
          <button
            type="button"
            className={tree ? 'btn fg-view-btn active' : 'btn fg-view-btn'}
            aria-pressed={tree}
            onClick={() => setView('tree')}
          >
            Tree
          </button>
        </div>
        {!tree && (
          <>
            <input
              className="input fg-name-input"
              aria-label="Name filter"
              placeholder="Filter by name"
              value={nameInput}
              onChange={(e) => setNameInput(e.target.value)}
            />
            <input
              className="input fg-ext-input"
              aria-label="Extension filter"
              placeholder="e.g. exe"
              value={extInput}
              onChange={(e) => setExtInput(e.target.value)}
            />
            <label className="fg-toggle">
              <input
                type="checkbox"
                aria-label="Deleted only"
                checked={deletedOnly}
                onChange={(e) =>
                  setParams({
                    deleted: e.target.checked ? 'true' : null,
                    page: null,
                  })
                }
              />
              Deleted only
            </label>
            <label className="fg-toggle">
              <input
                type="checkbox"
                aria-label="Unique only"
                checked={uniqueOnly}
                onChange={(e) =>
                  setParams({
                    unique: e.target.checked ? 'true' : null,
                    page: null,
                  })
                }
              />
              Unique only
            </label>
            <select
              className="select"
              aria-label="Known status filter"
              value={known}
              onChange={(e) =>
                setParams({ known: e.target.value || null, page: null })
              }
            >
              {KNOWN_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            <select
              className="select"
              aria-label="Page size"
              value={pageSize}
              onChange={(e) =>
                setParams({ page_size: e.target.value, page: null })
              }
            >
              {PAGE_SIZES.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </>
        )}
        {isRefetching && (
          <span className="fg-refetch" role="status">
            Refreshing…
          </span>
        )}
      </div>

      <div className="fg-crumb-bar">
        {tree ? (
          <span className="fg-crumbs mono">Expandable file-system tree</span>
        ) : flat ? (
          <span className="fg-crumbs mono">All files</span>
        ) : (
          <nav
            className="fg-crumbs mono"
            aria-label="Current folder"
            // The whole path stays on the element even when the middle of it
            // is collapsed, so hovering it and copying it out of the DOM both
            // still yield the path an examiner would quote.
            title={dir ?? undefined}
          >
            <button
              type="button"
              className="fg-crumb"
              aria-current={!dir ? 'page' : undefined}
              onClick={() => goToDir(null)}
            >
              Root
            </button>
            {shownCrumbs.map(({ name, index }, position) => (
              <Fragment key={`${name}-${index}`}>
                {hiddenCrumbs.length > 0 && position === 1 && (
                  <span className="fg-crumb-seg">
                    <span className="fg-crumb-sep">/</span>
                    <button
                      type="button"
                      className="fg-crumb fg-crumb-more"
                      aria-label={`${hiddenCrumbs.length} hidden folders`}
                      title={`${hiddenCrumbs.length} folders not shown`}
                      onClick={(event) => {
                        const box = event.currentTarget.getBoundingClientRect()
                        setCrumbMenu({ x: box.left, y: box.bottom + 4 })
                      }}
                    >
                      …
                    </button>
                  </span>
                )}
                <span className="fg-crumb-seg">
                  <span className="fg-crumb-sep">/</span>
                  <button
                    type="button"
                    className="fg-crumb"
                    aria-current={
                      index === dirSegments.length - 1 ? 'page' : undefined
                    }
                    onClick={() => goToDir(crumbPath(index))}
                  >
                    {name}
                  </button>
                </span>
              </Fragment>
            ))}
            {crumbMenu && (
              <ContextMenu
                x={crumbMenu.x}
                y={crumbMenu.y}
                header="Folders not shown in the path"
                items={hiddenCrumbs.map(({ name, index }) => ({
                  label: name,
                  onClick: () => goToDir(crumbPath(index)),
                }))}
                onClose={() => setCrumbMenu(null)}
              />
            )}
          </nav>
        )}
        {grid.data && !staleGrid && (
          <span className="fg-count" data-testid="fg-count">
            {/* Under a filter whose population is short — the scan capped, rows
                it could not read, or more matches than the grid will list —
                this count is a floor, and "4 items" would be a population claim
                nobody established. */}
            {grid.data.filter?.inventory_incomplete ? 'at least ' : ''}
            {formatCount(grid.data.total_count)} items
          </span>
        )}
      </div>

      {/* Present only when the server reported a filter, absent when it did
          not: a bar drawn from a filter_id the response never acknowledged
          would claim a narrowing that may not have happened. */}
      {!tree && grid.data && !staleGrid && grid.data.filter && (
        <FilterPopulationBar
          filter={grid.data.filter}
          onClear={() => {
            clearSelection()
            setParams({ filter_id: null, page: null })
          }}
        />
      )}

      {/* "Unique only" is a population-defining filter, so it says what it
          could not decide. A file with no hash is neither unique nor a
          duplicate; listing it would present an unknown as a finding, and
          dropping it silently would make the count read as "the case holds
          this many unique files" rather than "this many can be shown to be"
          (§2.8). */}
      {!tree && uniqueOnly && grid.data && !staleGrid && grid.data.unique && (
        <div
          className={
            grid.data.unique.unassessable > 0 ? 'warn-note' : 'dash-muted'
          }
          role="note"
          data-testid="fg-unique-note"
        >
          {grid.data.unique.note}
        </div>
      )}

      {/* Asked to show only unique files and told nothing about it: the rows
          cannot be read as "the files shown to be unique" without knowing what
          was set aside. */}
      {!tree && uniqueOnly && grid.data && !staleGrid && !grid.data.unique && (
        <div className="warn-note" role="note" data-testid="fg-unique-unreported">
          This view asked for unique files only, and the server did not say what
          the filter could not assess. The rows below may be the files shown to
          be unique, or the whole folder; until the server reports it, do not
          read this count as the number of unique files in the case.
        </div>
      )}

      {/* Asked for a filter, told nothing about one. The rows on screen cannot
          be read either as the filter's population or as the whole folder, and
          which of those it is decides what an absence here means. */}
      {!tree && filterId !== '' && grid.data && !staleGrid && !grid.data.filter && (
        <div
          className="warn-note"
          role="note"
          data-testid="fg-filter-unreported"
        >
          A filter was requested for this listing, but the server did not
          report which filter was applied or what it matched. These rows cannot
          be relied on as that filter&apos;s population.
        </div>
      )}

      {/* The tree lists the file system level by level and never sends
          filter_id, so a filter left in the URL while the tree is on screen
          would have the examiner reading the whole file system as the
          filter's population. */}
      {tree && filterId !== '' && (
        <div
          className="warn-note"
          role="note"
          data-testid="fg-filter-not-in-tree"
        >
          A filter is set on this view, but it is not applied in the tree: the
          tree lists the whole file system of this evidence source. Switch to
          Folders or All files to see the filter&apos;s population.
        </div>
      )}

      {tree ? (
        <>
          <div className="ft-wrap">
            <FileTree
              caseId={caseId}
              sourceId={sourceId}
              selectedId={treeSelected?.id ?? null}
              onSelect={setTreeSelected}
              onOpen={(row) => openArtifact(row.id)}
            />
          </div>
          {treeSelected && !treeSelected.is_directory && (
            <DetailPane
              caseId={caseId}
              item={treeSelected}
              onOpen={() => openArtifact(treeSelected.id)}
            />
          )}
        </>
      ) : flat ? (
        table
      ) : (
        <div className="fg-layout">
          <DirTree
            caseId={caseId}
            sourceId={sourceId}
            currentDirPath={dir ?? ''}
            onSelect={goToDir}
          />
          <div className="fg-main">{table}</div>
        </div>
      )}
    </div>
  )
}
