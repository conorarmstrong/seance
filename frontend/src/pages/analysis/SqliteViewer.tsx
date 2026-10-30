import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import {
  IncompletenessBanner,
  useIncompleteness,
} from '../../components/Incompleteness'
import type { ParsedRecord, RecordMetadata } from './api'
import { getAllRecords, getRecords } from './api'
import { MISSING, metaBool, metaNum, metaStr } from './lib'
import { decodeTimestamp, TIME_FORMATS, type TimeFormat } from './sqliteTime'
import { SqliteQueryEditor } from './SqliteQueryEditor'
import type { ViewerProps } from './viewers'
import { formatCount } from '../../lib/format'

/** Rows fetched per lazy page. */
const ROW_PAGE_SIZE = 200
/**
 * Hard cap on how many row pages are kept in the browser at once. Scrolling past
 * this evicts the oldest pages (react-query `maxPages`), so a huge table stays
 * bounded in memory instead of the whole table being read and held at once.
 */
const ROW_MAX_PAGES = 8

/** A value read as a 1-based page number, or null when it is not one. */
function pageNumber(v: unknown): number | null {
  return typeof v === 'number' && Number.isInteger(v) && v >= 1 ? v : null
}

/** Decode the `columns` field (object, or JSON string) to entries. */
function decodeColumns(meta: RecordMetadata): [string, string][] {
  let cols = meta['columns']
  if (typeof cols === 'string') {
    try {
      cols = JSON.parse(cols)
    } catch {
      return []
    }
  }
  if (cols && typeof cols === 'object' && !Array.isArray(cols)) {
    return Object.entries(cols as Record<string, unknown>).map(([k, v]) => [
      k,
      renderColumnValue(v),
    ])
  }
  return []
}

function renderColumnValue(v: unknown): string {
  if (v == null) return 'NULL'
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>
    if (o.blob === true) {
      const size = typeof o.size === 'number' ? o.size : '?'
      return `[blob ${size} bytes]`
    }
    try {
      return JSON.stringify(v)
    } catch {
      return String(v)
    }
  }
  return String(v)
}

function truncateValue(v: string, max = 120): string {
  return v.length > max ? `${v.slice(0, max)}…` : v
}

/** The value shown for a cell: the decoded date when a timestamp format is set
 * and the raw value decodes, otherwise the raw value. */
function cellDisplay(
  raw: string | undefined,
  fmt: TimeFormat | undefined,
): { text: string; decoded: boolean } | null {
  if (raw == null) return null
  if (fmt && fmt !== 'raw') {
    const d = decodeTimestamp(raw, fmt)
    if (d != null) return { text: d, decoded: true }
  }
  return { text: raw, decoded: false }
}

interface TableInfo {
  name: string
  live: number
  recovered: number
  rows: ParsedRecord[]
  /** Column keys in first-seen order across the table's rows. */
  columns: string[]
  /**
   * True when at least one of this table's rows is in the held row window.
   * False means the table is known from the database's schema but none of its
   * rows are loaded right now — which is a different statement from "this table
   * has no rows", and must never render as one.
   */
  inWindow: boolean
}

/** Recovered rows grouped by the database they came from. */
export interface DbInfo {
  name: string
  path: string | null
  rows: number
  tables: TableInfo[]
}

/** One database in the left rail, sourced from its (never-truncated) summary. */
export interface DbSummary {
  name: string
  path: string | null
  /** The database file's artifact id, used to scope its rows. */
  artifactId: string | null
  tableCount: number
  rowCount: number
  /**
   * Table names off the database's own schema, as the summary recorded them.
   * This is the complete list for the database and does not move as row pages
   * are fetched and evicted. Empty when the summary carried no readable
   * `tables` array (older ingests), in which case the table rail can only be
   * what the loaded rows show and says so.
   */
  tableNames: string[]
}

/** The `tables` field of a database summary: table names, or `[]` if unreadable. */
function decodeTableNames(meta: RecordMetadata): string[] {
  const raw = meta['tables']
  if (!Array.isArray(raw)) return []
  const out: string[] = []
  for (const v of raw) {
    if (typeof v === 'string' && v !== '' && !out.includes(v)) out.push(v)
  }
  return out
}

/**
 * Build the complete database list from `SqliteDatabaseForensics` summaries —
 * one per database, so it is never cut off by row pagination the way a list
 * derived from the first page of rows is. Summaries from before the identity
 * fields were added lack `database`; those are skipped and the caller falls back
 * to enumerating databases from the loaded rows.
 */
export function buildDbSummaries(records: ParsedRecord[]): DbSummary[] {
  const out: DbSummary[] = []
  for (const r of records) {
    const name = metaStr(r.metadata, 'database')
    if (!name) continue
    const tableNames = decodeTableNames(r.metadata)
    const rowCount =
      (metaNum(r.metadata, 'live_rows') ?? 0) +
      (metaNum(r.metadata, 'deleted_rows') ?? 0) +
      (metaNum(r.metadata, 'carved_rows') ?? 0)
    out.push({
      name,
      path: metaStr(r.metadata, 'database_path'),
      artifactId: metaStr(r.metadata, 'database_artifact'),
      tableCount: tableNames.length,
      rowCount,
      tableNames,
    })
  }
  return out.sort((a, b) => b.rowCount - a.rowCount || a.name.localeCompare(b.name))
}

function buildDatabases(records: ParsedRecord[]): DbInfo[] {
  const byDb = new Map<string, ParsedRecord[]>()
  for (const r of records) {
    // Rows parsed before the database was recorded fall into one bucket rather
    // than being hidden.
    const db = metaStr(r.metadata, 'database') ?? '(unknown database)'
    const list = byDb.get(db)
    if (list) list.push(r)
    else byDb.set(db, [r])
  }
  return [...byDb.entries()]
    .map(([name, rows]) => ({
      name,
      path: metaStr(rows[0].metadata, 'database_path'),
      rows: rows.length,
      tables: buildTables(rows),
    }))
    .sort((a, b) => b.rows - a.rows)
}

/**
 * The table rail for a database.
 *
 * `records` is only the row window currently held in the browser, so a rail
 * built from it alone silently loses every table whose rows are not in that
 * window — and a table that vanishes from the rail reads as "this database has
 * no such table". `schemaNames` is the database summary's own list of tables,
 * which does not move as pages are fetched and evicted; every name in it is
 * listed whether or not any of its rows are loaded, flagged `inWindow: false`
 * so the caller can say "no rows loaded" instead of "0 rows".
 */
export function buildTables(
  records: ParsedRecord[],
  schemaNames: string[] = [],
): TableInfo[] {
  const byName = new Map<string, TableInfo>()
  for (const r of records) {
    const name = metaStr(r.metadata, 'table') ?? '(unknown)'
    let info = byName.get(name)
    if (!info) {
      info = {
        name,
        live: 0,
        recovered: 0,
        rows: [],
        columns: [],
        inWindow: true,
      }
      byName.set(name, info)
    }
    const deleted = metaBool(r.metadata, 'deleted')
    if (deleted) info.recovered += 1
    else info.live += 1
    info.rows.push(r)
    for (const [k] of decodeColumns(r.metadata)) {
      if (!info.columns.includes(k)) info.columns.push(k)
    }
  }
  for (const name of schemaNames) {
    if (byName.has(name)) continue
    byName.set(name, {
      name,
      live: 0,
      recovered: 0,
      rows: [],
      columns: [],
      inWindow: false,
    })
  }
  // Tables with loaded rows first (most rows first), then the schema-only ones
  // in name order, so the rail's head stays stable as pages come and go.
  return [...byName.values()].sort((a, b) => {
    if (a.inWindow !== b.inWindow) return a.inWindow ? -1 : 1
    if (a.inWindow) return b.rows.length - a.rows.length
    return a.name.localeCompare(b.name)
  })
}

export function SqliteViewer({ caseId, type }: ViewerProps): ReactNode {
  const [sel, setSel] = useState<string | null>(null)
  const [selDb, setSelDb] = useState<string | null>(null)
  // Collapse the database / table rails to reclaim horizontal space.
  const [dbCollapsed, setDbCollapsed] = useState(false)
  const [tablesCollapsed, setTablesCollapsed] = useState(false)
  // The SQL editor for the active database. Closed by default: the grid is
  // the primary surface.
  const [sqlOpen, setSqlOpen] = useState(false)
  // Per-column view state, reset whenever the active table changes.
  const [colFmt, setColFmt] = useState<Record<string, TimeFormat>>({})
  const [hidden, setHidden] = useState<Set<string>>(new Set())
  const [filters, setFilters] = useState<Record<string, string>>({})

  // Phase 1: the complete database list, from the per-database summaries (one
  // each). Unlike a list built from the first page of rows, this is never cut
  // off by pagination — which is what makes later-ingested databases reliably
  // appear in the rail instead of silently dropping off the end.
  const dbQuery = useQuery({
    queryKey: ['analysis-sqlite-dbs', caseId],
    queryFn: () =>
      getAllRecords(caseId, 'SqliteDatabaseForensics', { maxPages: 50 }),
  })
  const summaries = useMemo(
    () => buildDbSummaries(dbQuery.data?.records ?? []),
    [dbQuery.data],
  )
  // The database-summary list is itself paged (maxPages); an extreme multi-DB
  // case can exceed the cap, so surface it rather than silently hiding databases.
  const dbsTruncated = dbQuery.data?.truncated ?? false
  // Cases ingested before summaries carried the database identity fall back to
  // enumerating databases from the loaded rows (bounded, but no worse than before).
  const useSummaries = summaries.length > 0

  const activeSummary =
    (selDb ? summaries.find((d) => d.name === selDb) : null) ?? summaries[0] ?? null

  // Phase 2: rows, lazily. With summaries, scope the fetch to the selected
  // database's artifact so one large database can't crowd the others out. Pages
  // are fetched on demand as the grid is scrolled, and `maxPages` evicts the
  // oldest once the window is full — so the whole table is never read into the
  // browser at once.
  const rowScope = useSummaries ? (activeSummary?.artifactId ?? undefined) : undefined
  const rowsQuery = useInfiniteQuery({
    queryKey: ['analysis-sqlite', caseId, type, rowScope ?? 'all'],
    initialPageParam: 1,
    queryFn: ({ pageParam }) =>
      getRecords(caseId, {
        type,
        page: pageParam as number,
        page_size: ROW_PAGE_SIZE,
        source_id: rowScope,
      }),
    // A short page means the database's rows are exhausted; otherwise advance
    // from the page param that produced this page.
    //
    // NOT from `allPages.length`: `maxPages` evicts the oldest page, so once the
    // window is full that length is pinned at ROW_MAX_PAGES and the cursor
    // sticks — every further fetch re-requests the same page, appends it again
    // and evicts a real one, so rows past the first window become unreachable
    // while the grid keeps claiming there is more to scroll (B4-002). The
    // third argument is the *last page param*, which react-query keeps in step
    // with the page it fetched and never rewrites on eviction.
    getNextPageParam: (last, _all, lastParam) => {
      if (last.records.length < ROW_PAGE_SIZE) return undefined
      // The server echoes the page it served; prefer it, and fall back to the
      // param we asked with. If neither is a usable page number we cannot
      // determine where to continue, and stopping silently would present a
      // partial table as the whole one — `rowCursorLost` below says so instead.
      const echoed = pageNumber(last.page)
      const asked = pageNumber(lastParam)
      const from = echoed ?? asked
      return from == null ? undefined : from + 1
    },
    maxPages: ROW_MAX_PAGES,
  })

  // The currently-held window of rows (bounded by ROW_MAX_PAGES), and the true
  // total for the database from the first page's count.
  const loadedRows = useMemo(
    () => (rowsQuery.data?.pages ?? []).flatMap((p) => p.records),
    [rowsQuery.data],
  )
  const rowTotal = rowsQuery.data?.pages?.[0]?.total ?? 0
  // Which slice of the database the held window actually is. With `maxPages`
  // the window slides, so "the first N rows" stops being true after the eighth
  // page and the grid must not keep saying it.
  const firstHeldPage = pageNumber(rowsQuery.data?.pageParams?.[0])
  const windowStart =
    firstHeldPage != null && loadedRows.length > 0
      ? (firstHeldPage - 1) * ROW_PAGE_SIZE + 1
      : null
  const windowEnd =
    windowStart != null ? windowStart + loadedRows.length - 1 : null
  // The cursor could not be advanced even though the last page came back full:
  // more rows exist than are shown and paging cannot reach them, which is a
  // different thing from having reached the end.
  const rowPages = rowsQuery.data?.pages ?? []
  const lastRowPage = rowPages.length > 0 ? rowPages[rowPages.length - 1] : null
  const rowCursorLost =
    lastRowPage != null &&
    lastRowPage.records.length >= ROW_PAGE_SIZE &&
    !rowsQuery.hasNextPage
  // Nothing was evicted and nothing is left to fetch: the window IS the whole
  // parsed row set for this database. A schema table with no rows here is then
  // a table this parse recovered no rows for — still not proof the table was
  // empty on the device, but telling the examiner to "scroll further" would be
  // an instruction that cannot be followed.
  const wholeSetHeld =
    firstHeldPage === 1 &&
    !rowsQuery.hasNextPage &&
    loadedRows.length >= rowTotal
  // Over the loaded window AND the database summaries: a summary carrying
  // `content_incomplete` is how a half-read database says so, and it is the
  // rail — not any one row — that the examiner picks a database from.
  const rowIncompleteness = useIncompleteness(loadedRows)
  const dbIncompleteness = useIncompleteness(dbQuery.data?.records)

  // Fallback database list (no usable summaries): grouped from the loaded rows.
  const fallbackDbs = useMemo(
    () => (useSummaries ? [] : buildDatabases(loadedRows)),
    [useSummaries, loadedRows],
  )

  // The left rail: complete from summaries, or the row-derived fallback.
  const railDbs: DbSummary[] = useSummaries
    ? summaries
    : fallbackDbs.map((d) => ({
        name: d.name,
        path: d.path,
        artifactId: null,
        tableCount: d.tables.length,
        rowCount: d.rows,
        tableNames: [],
      }))

  const activeName =
    (selDb && railDbs.some((d) => d.name === selDb) ? selDb : railDbs[0]?.name) ?? null
  const activeRailDb = railDbs.find((d) => d.name === activeName) ?? null

  // Tables for the active database: its schema's table list (complete, and
  // steady across page eviction) filled in from the rows in the held window, or
  // the pre-grouped fallback when there are no summaries to read a schema from.
  const tables: TableInfo[] = useSummaries
    ? buildTables(loadedRows, activeRailDb?.tableNames ?? [])
    : (fallbackDbs.find((d) => d.name === activeName)?.tables ?? [])
  // No schema list to lean on: the rail can only be what the window shows, and
  // saying so is the difference between "this database has three tables" and
  // "three tables have rows loaded".
  const railFromWindowOnly =
    !useSummaries || (activeRailDb?.tableNames.length ?? 0) === 0
  const active =
    sel && tables.some((t) => t.name === sel) ? sel : (tables[0]?.name ?? null)
  const table = tables.find((t) => t.name === active) ?? null

  useEffect(() => {
    setColFmt({})
    setHidden(new Set())
    setFilters({})
  }, [active])

  const visibleCols = (table?.columns ?? []).filter((c) => !hidden.has(c))
  const activeFilters = Object.entries(filters).filter(([, v]) => v.trim() !== '')

  // Decode each row's columns once (raw values), keyed by row id; reused by both
  // filtering and rendering instead of re-parsing metadata twice per render.
  const decodedByRow = useMemo(() => {
    const m = new Map<string, Map<string, string>>()
    for (const r of table?.rows ?? []) {
      m.set(r.id, new Map(decodeColumns(r.metadata)))
    }
    return m
  }, [table])

  const rows = (table?.rows ?? []).filter((r) => {
    if (activeFilters.length === 0) return true
    const cols = decodedByRow.get(r.id)
    return activeFilters.every(([c, f]) => {
      const disp = cellDisplay(cols?.get(c), colFmt[c])
      return (disp?.text ?? '').toLowerCase().includes(f.trim().toLowerCase())
    })
  })

  // Fetch the next page as the grid nears the bottom; react-query evicts the
  // oldest page once the window is full, keeping memory bounded.
  const gridRef = useRef<HTMLDivElement>(null)
  const onGridScroll = () => {
    const el = gridRef.current
    if (!el) return
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 400
    if (nearBottom && rowsQuery.hasNextPage && !rowsQuery.isFetchingNextPage) {
      void rowsQuery.fetchNextPage()
    }
  }

  if (dbQuery.isPending || rowsQuery.isPending)
    return <div className="loading">Loading rows…</div>
  if (rowsQuery.isError) {
    return <div className="error-note">{(rowsQuery.error as Error).message}</div>
  }
  if (railDbs.length === 0) {
    return (
      <div className="empty-state">
        <h3>No recovered rows</h3>
        <p>No SQLite rows were recovered for this database.</p>
      </div>
    )
  }

  return (
    <div
      className={`an-db${dbCollapsed ? ' db-collapsed' : ''}${
        tablesCollapsed ? ' tables-collapsed' : ''
      }`}
    >
      {dbCollapsed ? (
        <button
          type="button"
          className="an-db-rail-collapsed"
          title="Show databases"
          aria-label="Show databases"
          onClick={() => setDbCollapsed(false)}
        >
          <ChevronRight size={14} />
          <span className="an-db-rail-label">Databases</span>
        </button>
      ) : (
        <aside className="an-db-list" aria-label="Databases">
          <div className="an-db-head">
            <span>Databases</span>
            <button
              type="button"
              className="an-db-collapse"
              title="Collapse"
              aria-label="Collapse databases"
              onClick={() => setDbCollapsed(true)}
            >
              <ChevronLeft size={14} />
            </button>
          </div>
          {dbsTruncated && (
            <div className="an-chat-note" role="note">
              Too many databases to list them all; some are not shown in this rail.
            </div>
          )}
          <IncompletenessBanner summary={dbIncompleteness} noun="databases" />
          {railDbs.map((d) => (
          <button
            key={d.name}
            type="button"
            className={
              d.name === activeName ? 'an-db-item selected' : 'an-db-item'
            }
            data-testid="an-db-item"
            title={d.path ?? d.name}
            onClick={() => {
              setSelDb(d.name)
              // A table name means nothing across databases; start fresh.
              setSel(null)
            }}
          >
            <span className="an-db-item-name mono">{d.name}</span>
            <span className="an-db-item-meta">
              {d.tableCount} table{d.tableCount === 1 ? '' : 's'} ·{' '}
              {formatCount(d.rowCount)} rows
            </span>
          </button>
          ))}
        </aside>
      )}

      {tablesCollapsed ? (
        <button
          type="button"
          className="an-db-rail-collapsed"
          title="Show tables"
          aria-label="Show tables"
          onClick={() => setTablesCollapsed(false)}
        >
          <ChevronRight size={14} />
          <span className="an-db-rail-label">Tables</span>
        </button>
      ) : (
      <aside className="an-db-tables" aria-label="Tables">
        <div className="an-db-head" title={activeRailDb?.path ?? undefined}>
          <span>{activeName ?? 'Tables'}</span>
          <button
            type="button"
            className="an-db-collapse"
            title="Collapse"
            aria-label="Collapse tables"
            onClick={() => setTablesCollapsed(true)}
          >
            <ChevronLeft size={14} />
          </button>
        </div>
        {rowTotal > loadedRows.length && (
          <div className="an-chat-note" data-testid="an-db-window-note">
            {windowStart != null && windowEnd != null
              ? `Rows ${formatCount(windowStart)}–${formatCount(windowEnd)} of ${formatCount(rowTotal)}`
              : `${formatCount(loadedRows.length)} of ${formatCount(rowTotal)} rows`}{' '}
            {useSummaries ? 'in this database ' : ''}are loaded; scroll the grid
            to page on. At most{' '}
            {formatCount(ROW_PAGE_SIZE * ROW_MAX_PAGES)} rows are held at
            once, so earlier rows leave the window as later ones arrive — every
            count on this rail describes the loaded window, not the whole
            database.
          </div>
        )}
        {rowCursorLost && (
          <div className="warn-note" role="note" data-testid="an-db-cursor-lost">
            The last page of rows came back full but the server did not say which
            page it was, so paging cannot continue. More rows exist than are
            shown here and this viewer cannot reach them.
          </div>
        )}
        {railFromWindowOnly && rowTotal > loadedRows.length && (
          <div className="an-chat-note" data-testid="an-db-rail-window-only">
            This database's summary carried no table list, so these are only the
            tables with rows in the loaded window — not necessarily every table
            in the database.
          </div>
        )}
        {tables.map((t) => (
          <button
            key={t.name}
            type="button"
            className={t.name === active ? 'an-db-table selected' : 'an-db-table'}
            data-testid="an-db-table"
            onClick={() => setSel(t.name)}
          >
            <span className="an-db-table-name mono">{t.name}</span>
            <span className="an-db-table-counts">
              {t.inWindow ? (
                <>
                  {/* Counted over the held row window, never over the table:
                      labelling a window count as the table's row count is the
                      same false claim as hiding the table altogether. */}
                  <span
                    className="badge badge-ok"
                    title="Live rows in the loaded window"
                  >
                    {t.live} live
                  </span>
                  {t.recovered > 0 && (
                    <span
                      className="badge badge-danger"
                      title="Recovered (deleted) rows in the loaded window"
                    >
                      {t.recovered} recovered
                    </span>
                  )}
                </>
              ) : (
                <span
                  className="badge badge-warn"
                  title="This table is in the database's schema, but none of its rows are in the row window currently loaded. That is not a statement that the table is empty."
                >
                  no rows loaded
                </span>
              )}
            </span>
          </button>
        ))}
      </aside>
      )}

      <section className="an-db-grid-wrap" aria-label="Rows">
        <div className="an-db-gridbar">
          <button
            type="button"
            className="btn"
            aria-expanded={sqlOpen}
            onClick={() => setSqlOpen((o) => !o)}
          >
            {sqlOpen ? 'Hide SQL query' : 'SQL query'}
          </button>
        </div>
        {sqlOpen && activeRailDb != null && (
          // Keyed on the database so a result for one database is never left
          // on screen under another database's heading.
          <SqliteQueryEditor
            key={activeRailDb.artifactId ?? activeRailDb.name}
            caseId={caseId}
            database={{
              name: activeRailDb.name,
              artifactId: activeRailDb.artifactId,
              tableNames: activeRailDb.tableNames,
            }}
          />
        )}
        {/* This viewer loads its own rows and its own database summaries, so
            the page-level banner (over RecordsViewerPage's page-1 fetch) does
            not cover what is on screen here. A database the parser stopped
            reading part-way stamps the standard pair on the rows it did get,
            and an examiner reading a table needs that beside the table. */}
        <IncompletenessBanner summary={rowIncompleteness} noun="loaded rows" />
        {table != null && !table.inWindow && (
          <div className="warn-note" role="note" data-testid="an-db-table-unloaded">
            {wholeSetHeld ? (
              <>
                Every row this parse recovered from the database is loaded, and
                none of them belongs to{' '}
                <span className="mono">{table.name}</span>. That is a statement
                about the rows the parser recovered, not a finding that the
                table was empty on the device.
              </>
            ) : (
              <>
                No rows of <span className="mono">{table.name}</span> are in the
                row window currently loaded. Scroll the grid to page further
                through this database. An empty grid here is not a finding that
                the table is empty.
              </>
            )}
          </div>
        )}
        {(hidden.size > 0 || activeFilters.length > 0) && (
          <div className="an-db-gridbar">
            {activeFilters.length > 0 && (
              <span className="an-db-gridbar-count">
                {formatCount(rows.length)} of{' '}
                {formatCount(table?.rows.length ?? 0)} rows
              </span>
            )}
            {hidden.size > 0 && (
              <button
                type="button"
                className="link-button"
                onClick={() => setHidden(new Set())}
              >
                Show {hidden.size} hidden column{hidden.size === 1 ? '' : 's'}
              </button>
            )}
          </div>
        )}
        <div
          className="an-db-grid-scroll"
          data-testid="an-db-grid-scroll"
          ref={gridRef}
          onScroll={onGridScroll}
        >
          <table className="data-table an-table an-db-grid">
            <thead>
              <tr>
                <th>State</th>
                <th>Row ID</th>
                {visibleCols.map((c) => (
                  <th key={c} className="mono an-db-col">
                    <div className="an-db-col-head">
                      <span className="an-db-col-name" title={c}>
                        {c}
                      </span>
                      <button
                        type="button"
                        className="an-db-col-hide"
                        aria-label={`Hide column ${c}`}
                        title="Hide column"
                        onClick={() =>
                          setHidden((h) => new Set(h).add(c))
                        }
                      >
                        ×
                      </button>
                    </div>
                    <select
                      className="an-db-col-fmt"
                      aria-label={`Interpret ${c} as`}
                      value={colFmt[c] ?? 'raw'}
                      onChange={(e) =>
                        setColFmt((f) => ({
                          ...f,
                          [c]: e.target.value as TimeFormat,
                        }))
                      }
                    >
                      {TIME_FORMATS.map((tf) => (
                        <option key={tf.id} value={tf.id}>
                          {tf.label}
                        </option>
                      ))}
                    </select>
                  </th>
                ))}
                <th>Recovery</th>
                <th>Confidence</th>
              </tr>
              <tr className="an-db-filter-row">
                <th />
                <th />
                {visibleCols.map((c) => (
                  <th key={c}>
                    <input
                      className="an-db-filter"
                      type="text"
                      placeholder="filter"
                      aria-label={`Filter ${c}`}
                      value={filters[c] ?? ''}
                      onChange={(e) =>
                        setFilters((f) => ({ ...f, [c]: e.target.value }))
                      }
                    />
                  </th>
                ))}
                <th />
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const m = r.metadata
                const deleted = metaBool(m, 'deleted')
                const cols = decodedByRow.get(r.id) ?? new Map<string, string>()
                return (
                  <tr
                    key={r.id}
                    tabIndex={0}
                    className={deleted ? 'an-row-deleted' : undefined}
                    data-testid={deleted ? 'sqlite-deleted-row' : 'sqlite-live-row'}
                  >
                    <td>
                      {deleted ? (
                        <span className="badge badge-danger">deleted</span>
                      ) : (
                        <span className="badge badge-ok">live</span>
                      )}
                    </td>
                    <td className="mono">{metaStr(m, 'rowid') ?? MISSING}</td>
                    {visibleCols.map((c) => {
                      const disp = cellDisplay(cols.get(c), colFmt[c])
                      if (disp == null) {
                        return (
                          <td key={c} className="mono">
                            {MISSING}
                          </td>
                        )
                      }
                      return (
                        <td
                          key={c}
                          className={disp.decoded ? 'mono an-db-ts' : 'mono'}
                          title={disp.decoded ? cols.get(c) : disp.text}
                        >
                          {truncateValue(disp.text)}
                        </td>
                      )
                    })}
                    <td className="mono">{metaStr(m, 'recovery_source') ?? MISSING}</td>
                    <td className="mono">{metaStr(m, 'confidence') ?? MISSING}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {rowsQuery.isFetchingNextPage && (
            <div className="an-db-grid-more" aria-live="polite">
              Loading more rows…
            </div>
          )}
        </div>
      </section>
    </div>
  )
}
