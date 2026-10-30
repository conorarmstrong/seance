import { useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { Download, Play, Plus, Table2, Trash2, Upload } from 'lucide-react'
import { ContextMenu } from '../../components/ContextMenu'
import { useToast } from '../../components/toast/ToastProvider'
import { getSourceStats } from '../dashboard/api'
import type { SavedFilter } from '../../api/types'
import {
  applyFilter,
  createFilter,
  deleteFilter,
  listFilters,
  type FilterApplyResult,
} from '../../api/resources'
import {
  buildConditionFromRows,
  describeCondition,
  FILTER_OPS,
  type ConditionRow,
  type FilterOp,
} from './filterModel'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { formatCount } from '../../lib/format'
import { QuickFilterBar, useQuickFilter } from '../../components/QuickFilter'
import './filters.css'

/** Trigger a client-side download of a filter as a shareable JSON file. */
function downloadFilter(filter: SavedFilter) {
  const doc = {
    name: filter.name,
    description: filter.description,
    filter: filter.filter,
  }
  const blob = new Blob([JSON.stringify(doc, null, 2)], {
    type: 'application/json',
  })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `filter-${filter.name.replace(/[^\w.-]+/g, '_')}.json`
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  // Defer revocation: revoking synchronously right after click() can abort the
  // download before the browser reads the blob, yielding an empty/truncated
  // filter JSON on some browsers (BUG-203, same pattern as BUG-169).
  setTimeout(() => URL.revokeObjectURL(url), 60_000)
}

/** A blank builder row. The id is a React key only; it never leaves the page. */
let rowSeq = 0
function newRow(): ConditionRow {
  rowSeq += 1
  return {
    id: `row-${rowSeq}`,
    field: 'extension',
    operator: 'eq',
    value: '',
    negated: false,
  }
}

/**
 * The file grid, showing one filter's population under one evidence source.
 *
 * "All files" rather than the folder view: a filter's population spans the
 * whole file system, and the folder view lists a single path level, which would
 * intersect the population with whatever directory the grid was last in and
 * show a fraction of it under the filter's name.
 */
function gridUrl(caseId: string, sourceId: string, filterId: string): string {
  return `/cases/${caseId}/files/${sourceId}?view=flat&filter_id=${filterId}`
}

export function FiltersPage() {
  const { caseId = '' } = useParams()
  const navigate = useNavigate()
  const toast = useToast()
  const qc = useQueryClient()
  const fileInput = useRef<HTMLInputElement>(null)

  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  // The builder's rows. A flat list joined by ONE connective, with negation on
  // the row it inverts: that is the most a form of this shape can express
  // without a precedence question, and a filter whose meaning depends on
  // precedence the screen does not draw is a filter that defines a population
  // nobody can check. Arbitrary trees still arrive by import and are still
  // rendered (parenthesised) by `describeCondition`; what the builder declines
  // is to CREATE one it could not draw.
  const [conditionRows, setConditionRows] = useState<ConditionRow[]>([newRow()])
  const [logic, setLogic] = useState<'and' | 'or'>('and')
  // This page stays mounted across a `:caseId` route change, so the applied
  // result set — a match count plus artifact ids belonging to case A — would
  // otherwise render under case B's chrome, with each row linking to
  // /cases/<caseB>/artifacts/<idFromA> (BUG-260).
  //
  // Clearing it in a `useEffect` keyed on the case left one committed frame in
  // which exactly that mislabelled result table was painted: "1,204 matches"
  // under case B's heading, every row a link into case B carrying case A's
  // artifact id. Storing the result with the case it was produced for and
  // resolving during render removes the frame rather than correcting it after
  // the fact (B2-147).
  const [applied, setApplied] = useEntityScopedState<{
    filter: SavedFilter
    result: FilterApplyResult
  } | null>(caseId, null)

  // The case a mutation must have been sent to in order for its result to be
  // owned here. Assigned during render, not from an effect: a request that
  // settles between the switching render and its passive effects would
  // otherwise be checked against the PREVIOUS case and land under the new one.
  const activeCase = useRef(caseId)
  activeCase.current = caseId

  const filters = useQuery({
    queryKey: ['filters', caseId],
    queryFn: () => listFilters(caseId),
    enabled: caseId !== '',
  })

  // The case's evidence sources, for "Open in file grid" below. Under the same
  // query key the dashboard's own sources section uses, so reaching this page
  // from the dashboard costs no second request and cannot show a different
  // list of exhibits than the dashboard just showed.
  const sources = useQuery({
    queryKey: ['case', caseId, 'stats', 'sources'],
    queryFn: () => getSourceStats(caseId),
    enabled: caseId !== '',
  })
  const sourceRows = sources.data?.sources ?? []

  // Which filter's "Open in file grid" menu is open, and where to draw it.
  const [gridMenu, setGridMenu] = useState<{
    x: number
    y: number
    filter: SavedFilter
  } | null>(null)

  /**
   * The grid is scoped to ONE evidence source and a filter is evaluated over
   * the whole case, so which exhibit to open it under is a choice the examiner
   * has to make rather than one this page can make for them. It is skipped only
   * when the case holds exactly one source, where there is nothing to choose.
   */
  function openInGrid(filter: SavedFilter, opener: HTMLElement) {
    if (sourceRows.length === 1) {
      navigate(gridUrl(caseId, sourceRows[0].source_artifact_id, filter.id))
      return
    }
    const box = opener.getBoundingClientRect()
    setGridMenu({ x: box.left, y: box.bottom + 4, filter })
  }

  const invalidate = (forCase: string) =>
    qc.invalidateQueries({ queryKey: ['filters', forCase] })

  // A create or delete still in flight when the case changes completes against
  // the case it was sent to, but `onSuccess` runs in the render's latest
  // closure. Reading `caseId` there confirmed "Filter saved" over case B's list
  // while the filter was written to case A, and refreshed case B's list while
  // case A's — the one that actually changed — kept showing stale rows. Carry
  // the case the request was sent to through the mutation, the way the apply
  // path already does (B2-119).
  const create = useMutation({
    mutationFn: (body: { name: string; description?: string; filter: unknown }) => {
      const forCase = caseId
      return createFilter(forCase, body).then(() => ({ forCase }))
    },
    onSuccess: ({ forCase }) => {
      void invalidate(forCase)
      if (forCase !== activeCase.current) return
      toast.success('Filter saved')
      setName('')
      setDescription('')
      setConditionRows([newRow()])
      setLogic('and')
    },
    onError: (e) => toast.error((e as Error).message),
  })

  const remove = useMutation({
    mutationFn: (id: string) => {
      const forCase = caseId
      return deleteFilter(forCase, id).then(() => ({ forCase }))
    },
    onSuccess: ({ forCase }) => {
      void invalidate(forCase)
      if (forCase !== activeCase.current) return
      toast.success('Filter deleted')
    },
    onError: (e) => toast.error((e as Error).message),
  })

  const run = useMutation({
    mutationFn: (filter: SavedFilter) =>
      applyFilter(caseId, filter.id).then((result) => ({
        result,
        forCase: caseId,
      })),
    // An apply still in flight when the case changes must be disowned, not
    // landed under the new case (BUG-260).
    onSuccess: ({ result, forCase }, filter) => {
      if (forCase !== activeCase.current) return
      setApplied({ filter, result })
    },
    onError: (e) => toast.error((e as Error).message),
  })

  // Recomputed every render rather than held in state, so the sentence under
  // the form and the JSON the Save button would send can never disagree: they
  // are the same value.
  const drafted = buildConditionFromRows(conditionRows, logic)
  const draftError = 'error' in drafted ? drafted.error : null

  function updateRow(id: string, patch: Partial<ConditionRow>) {
    setConditionRows((prev) =>
      prev.map((row) => (row.id === id ? { ...row, ...patch } : row)),
    )
  }

  function onCreate(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) {
      toast.error('A filter needs a name.')
      return
    }
    if ('error' in drafted) {
      toast.error(drafted.error)
      return
    }
    create.mutate({
      name: name.trim(),
      description: description.trim() || undefined,
      filter: drafted.condition,
    })
  }

  async function onImport(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = '' // allow re-importing the same file
    if (!file) return
    try {
      const doc = JSON.parse(await file.text())
      // Accept a full {name, filter} document or a bare condition object.
      const cond = doc.filter ?? doc
      const importedName =
        typeof doc.name === 'string' && doc.name
          ? doc.name
          : file.name.replace(/\.json$/i, '')
      if (!cond || typeof cond !== 'object' || !('type' in cond)) {
        toast.error('Not a valid filter file')
        return
      }
      create.mutate({
        name: importedName,
        description:
          typeof doc.description === 'string' ? doc.description : undefined,
        filter: cond,
      })
    } catch {
      toast.error('Could not read filter JSON')
    }
  }

  const all = filters.data ?? []
  // A quick type-ahead over the filter library (§1.1). The whole library is
  // loaded, so the bar claims nothing about a subset.
  const search = useQuickFilter(caseId, all, (f) => [
    f.name,
    f.description,
    describeCondition(f.filter),
  ])
  const rows = search.rows

  return (
    <div>
      <h1 className="page-title">Filters</h1>
      <p className="flt-lead">
        Save reusable filter conditions, apply them to the evidence, and share
        them between cases with import / export.
      </p>

      <div className="flt-layout">
        <section className="flt-list" aria-label="Saved filters">
          <div className="flt-list-head">
            <h2>Saved &amp; predefined</h2>
            <button
              type="button"
              className="btn"
              onClick={() => fileInput.current?.click()}
            >
              <Upload size={14} /> Import
            </button>
            <input
              ref={fileInput}
              type="file"
              accept="application/json,.json"
              className="flt-file"
              aria-label="Import filter JSON"
              onChange={onImport}
            />
          </div>

          {all.length > 0 && (
            <QuickFilterBar
              filter={search}
              noun="filter"
              placeholder="Filter the library…"
            />
          )}

          {filters.isPending ? (
            <div className="loading">Loading filters…</div>
          ) : filters.isError ? (
            <div className="error-note">
              Failed to load filters — retry or check the server.
            </div>
          ) : all.length === 0 ? (
            <div className="empty-state">
              <h3>No filters</h3>
              <p>Create one below, or import a shared filter.</p>
            </div>
          ) : rows.length === 0 ? (
            // The library has filters and the needle matched none of them.
            // Saying "no filters" here would read as an empty library.
            <div className="empty-state">
              <h3>No filter matches that</h3>
              <p>
                This case has {all.length} saved or predefined{' '}
                {all.length === 1 ? 'filter' : 'filters'}; none of them matches
                what you typed. Clear the box to see them all.
              </p>
            </div>
          ) : (
            <ul className="flt-items">
              {rows.map((f) => (
                <li key={f.id} className="flt-item">
                  <div className="flt-item-main">
                    <span className="flt-item-name">{f.name}</span>
                    {f.is_predefined && (
                      <span className="badge">predefined</span>
                    )}
                    {f.description && (
                      <span className="flt-item-desc">{f.description}</span>
                    )}
                    <code className="flt-item-cond">
                      {describeCondition(f.filter)}
                    </code>
                  </div>
                  <div className="flt-item-actions">
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => run.mutate(f)}
                      disabled={run.isPending}
                      title="Apply this filter"
                    >
                      <Play size={13} /> Apply
                    </button>
                    {/* The results table on this page is a preview; the file
                        grid has the paging, sort, selection and export. What it
                        does not have is a way to reach a filter's population,
                        which is what this hands it. */}
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={(event) => openInGrid(f, event.currentTarget)}
                      disabled={sourceRows.length === 0}
                      title={
                        sources.isPending
                          ? 'Loading the evidence sources of this case…'
                          : sources.isError
                            ? 'The evidence sources of this case could not be loaded, so there is nothing to open the population in.'
                            : sourceRows.length === 0
                              ? 'This case has no evidence source with a file system to open the population in.'
                              : 'List this filter\u2019s matching files in the file grid'
                      }
                    >
                      <Table2 size={13} /> Open in file grid
                    </button>
                    <button
                      type="button"
                      className="icon-btn"
                      onClick={() => downloadFilter(f)}
                      aria-label={`Export ${f.name}`}
                      title="Export as JSON"
                    >
                      <Download size={14} />
                    </button>
                    {!f.is_predefined && (
                      <button
                        type="button"
                        className="icon-btn"
                        onClick={() => remove.mutate(f.id)}
                        aria-label={`Delete ${f.name}`}
                        title="Delete filter"
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}

          {/* One menu for the whole list rather than one per row: it is a
              portal, and which filter it is about travels in its own state. */}
          {gridMenu && (
            <ContextMenu
              x={gridMenu.x}
              y={gridMenu.y}
              header={
                sources.data?.inventory_incomplete
                  ? 'Open in file grid — this list of evidence sources may be incomplete'
                  : 'Open in file grid — which evidence source?'
              }
              items={sourceRows.map((source) => ({
                label: source.name,
                // A source whose name the server could not resolve is listed
                // under its UUID, and says so, rather than being left out of a
                // menu that is offered as the case's exhibits.
                note:
                  source.name_resolved === false
                    ? 'name could not be resolved; shown as its artifact id'
                    : undefined,
                onClick: () =>
                  navigate(
                    gridUrl(caseId, source.source_artifact_id, gridMenu.filter.id),
                  ),
              }))}
              onClose={() => setGridMenu(null)}
            />
          )}

          <form className="flt-new" onSubmit={onCreate}>
            <h3>New filter</h3>
            <div className="flt-new-row">
              <input
                className="input"
                aria-label="Filter name"
                placeholder="Filter name"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
              <input
                className="input"
                aria-label="Filter description"
                placeholder="Description (optional)"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>

            {/* The connective appears only once there is something to join.
                Shown earlier it would ask the examiner to choose between two
                readings of a single condition, which are the same reading. */}
            {conditionRows.length > 1 && (
              <label className="flt-join">
                Match
                <select
                  className="select"
                  aria-label="Join conditions"
                  value={logic}
                  onChange={(e) => setLogic(e.target.value as 'and' | 'or')}
                >
                  <option value="and">all</option>
                  <option value="or">any</option>
                </select>
                of these conditions
              </label>
            )}

            {conditionRows.map((row, index) => (
              <div className="flt-new-row flt-cond-row" key={row.id}>
                <label className="flt-negate">
                  <input
                    type="checkbox"
                    aria-label={`Negate condition ${index + 1}`}
                    checked={row.negated}
                    onChange={(e) =>
                      updateRow(row.id, { negated: e.target.checked })
                    }
                  />
                  NOT
                </label>
                <input
                  className="input"
                  aria-label={`Field ${index + 1}`}
                  placeholder="field (e.g. extension)"
                  value={row.field}
                  onChange={(e) => updateRow(row.id, { field: e.target.value })}
                />
                <select
                  className="select"
                  aria-label={`Operator ${index + 1}`}
                  value={row.operator}
                  onChange={(e) =>
                    updateRow(row.id, { operator: e.target.value as FilterOp })
                  }
                >
                  {FILTER_OPS.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.label}
                    </option>
                  ))}
                </select>
                <input
                  className="input"
                  aria-label={`Value ${index + 1}`}
                  placeholder={row.operator === 'in' ? 'exe, dll, sys' : 'value'}
                  value={row.value}
                  onChange={(e) => updateRow(row.id, { value: e.target.value })}
                  disabled={row.operator === 'exists'}
                />
                <button
                  type="button"
                  className="icon-btn"
                  aria-label={`Remove condition ${index + 1}`}
                  title="Remove this condition"
                  onClick={() =>
                    setConditionRows((prev) =>
                      prev.filter((r) => r.id !== row.id),
                    )
                  }
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))}

            <div className="flt-new-row flt-new-actions">
              <button
                type="button"
                className="btn"
                onClick={() => setConditionRows((prev) => [...prev, newRow()])}
              >
                <Plus size={14} /> Add condition
              </button>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={create.isPending}
              >
                Save
              </button>
            </div>

            {/* What this filter will actually ask of the evidence, in the same
                words the saved-filter list uses, so the sentence an examiner
                checks before saving is the sentence they will read afterwards.
                A refusal replaces it rather than sitting beside it: there is no
                condition to describe while the form does not define one. */}
            {draftError ? (
              <p className="error-note" role="note">
                {draftError}
              </p>
            ) : (
              <p className="flt-preview-line">
                This filter matches artifacts where{' '}
                <code data-testid="flt-preview">
                  {describeCondition(
                    'condition' in drafted ? drafted.condition : null,
                  )}
                </code>
              </p>
            )}
          </form>
        </section>

        <section className="flt-results" aria-label="Filter results">
          {applied == null ? (
            <div className="empty-state">
              <h3>No filter applied</h3>
              <p>Apply a filter to see the matching artifacts here.</p>
            </div>
          ) : (
            <>
              <p className="flt-results-meta">
                <strong>{applied.filter.name}</strong> —{' '}
                {formatCount(applied.result.total)} matches
                {applied.result.results.length < applied.result.total &&
                  ` (showing first ${applied.result.results.length})`}
              </p>
              {/* The case-wide scan stops at a row ceiling. When it did, or
                  when the server did not say, `total` is a floor and an
                  absence below is not evidence of absence (B6-008). */}
              {applied.result.scan_complete === false && (
                <div
                  className="warn-note"
                  role="note"
                  data-testid="flt-scan-incomplete"
                >
                  The scan stopped at the case-wide row ceiling before reaching
                  the end of this case. {formatCount(applied.result.total)}{' '}
                  is the number of matches found so far, not the number that
                  exist — artifacts this filter would match were never examined.
                </div>
              )}
              {/* A scan that ran to the end and could not read some rows is
                  short in a way paging cannot repair, and `scan_complete` is
                  true for it. Without this, such a result rendered as an
                  unqualified match count — and "0 matches" from a scan that
                  skipped rows is an absence conclusion nobody established
                  (B8-028). */}
              {(applied.result.undecodable ?? 0) > 0 && (
                <div
                  className="warn-note"
                  role="note"
                  data-testid="flt-scan-undecodable"
                >
                  {formatCount(applied.result.undecodable!)} artifact
                  {applied.result.undecodable === 1 ? '' : 's'} could not be
                  read while this filter ran, so{' '}
                  {formatCount(applied.result.total)} is a floor. They may
                  or may not have matched; the scan reached them and could not
                  say.
                </div>
              )}
              {applied.result.scan_complete === undefined && (
                <div
                  className="warn-note"
                  role="note"
                  data-testid="flt-scan-unknown"
                >
                  The server did not report whether the scan covered the whole
                  case, so whether{' '}
                  {formatCount(applied.result.total)} is the complete match
                  count cannot be established from this response.
                </div>
              )}
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Name</th>
                  </tr>
                </thead>
                <tbody>
                  {applied.result.results.map((r) => (
                    <tr key={r.id}>
                      <td>
                        <span className="badge badge-accent">
                          {r.artifact_type}
                        </span>
                      </td>
                      <td>
                        <Link to={`/cases/${caseId}/artifacts/${r.id}`}>
                          {String(r.metadata?.name ?? r.metadata?.path ?? r.id)}
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </section>
      </div>
    </div>
  )
}
