import { useEffect, useState, type FormEvent } from 'react'
import { HelpCircle } from 'lucide-react'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import type { AnalysisFilter } from './analysis'
import { formatCount } from '../../lib/format'

export interface TimelineFilters {
  search: string
  range: string
  from: string | null
  to: string | null
  modules: string[]
  taggedOnly: boolean
  pageSize: number
}

/** Values accepted by the API `range` query param. */
const RANGE_PRESETS: { value: string; label: string }[] = [
  { value: '', label: 'All time' },
  { value: 'today', label: 'Today' },
  { value: 'yesterday', label: 'Yesterday' },
  { value: 'this_week', label: 'This week' },
  { value: 'this_month', label: 'This month' },
  { value: 'this_year', label: 'This year' },
  { value: '24h', label: 'Last 24h' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
]

const PAGE_SIZES = [50, 100, 250, 500]

/** Unix seconds -> value for a datetime-local input, interpreted as UTC. */
function unixToLocalInput(unix: string | null): string {
  if (!unix) return ''
  const ms = Number(unix) * 1000
  if (Number.isNaN(ms)) return ''
  return new Date(ms).toISOString().slice(0, 16)
}

/** datetime-local value (treated as UTC) -> unix seconds string, or null. */
function localInputToUnix(value: string): string | null {
  if (!value) return null
  const ms = Date.parse(`${value}Z`)
  if (Number.isNaN(ms)) return null
  return String(Math.floor(ms / 1000))
}

export type ExportFormat = 'json' | 'csv' | 'pdf' | 'sqlite' | 'body_events'

export function TimelineToolbar({
  caseId,
  filters,
  moduleCounts,
  totalCount,
  exporting,
  analysisFilter,
  onChange,
  onExport,
  onOpenColumns,
  onAnalysisFilterChange,
}: {
  caseId: string
  filters: TimelineFilters
  moduleCounts: Record<string, number> | undefined
  totalCount: number | undefined
  exporting: ExportFormat | null
  analysisFilter: AnalysisFilter
  onChange: (patch: Record<string, string | null>) => void
  onExport: (format: ExportFormat) => void
  onOpenColumns: () => void
  onAnalysisFilterChange: (value: AnalysisFilter) => void
}) {
  // The typed-but-unsubmitted search belongs to the case it was typed against.
  // The timeline page stays mounted across a `:caseId` change, and the effect
  // below only re-syncs when the APPLIED search (the URL) moves — so switching
  // from case A (draft "chrome.exe", nothing submitted) to case B (no `search`
  // param) leaves the draft in the box. Submitting it then filters case B's
  // timeline by a term chosen while reading case A, and an empty result reads
  // as "case B has no such activity". Scoped so the box is empty in the first
  // frame of the new case, not one effect later.
  const [searchText, setSearchText] = useEntityScopedState(
    caseId,
    filters.search,
  )
  const [helpOpen, setHelpOpen] = useState(false)
  const [modulesOpen, setModulesOpen] = useState(false)

  // The URL is the source of truth for the applied search; mirror it into
  // the input whenever it changes (back/forward navigation, external
  // resets). Typed-but-unsubmitted text only survives until the URL moves.
  useEffect(() => {
    setSearchText(filters.search)
  }, [filters.search])

  const submitSearch = (e: FormEvent) => {
    e.preventDefault()
    onChange({ search: searchText.trim() || null })
  }

  const toggleModule = (module: string, checked: boolean) => {
    const next = checked
      ? [...filters.modules, module]
      : filters.modules.filter((m) => m !== module)
    onChange({ modules: next.join(',') || null })
  }

  const moduleNames = Object.keys(moduleCounts ?? {}).sort()

  return (
    <div className="tl-toolbar">
      <div className="tl-toolbar-row">
        <form className="tl-search-wrap" onSubmit={submitSearch}>
          <input
            className="input tl-search"
            placeholder="Search timeline…"
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            aria-label="Search timeline"
          />
          <button
            type="button"
            className="btn btn-icon"
            aria-label="Search syntax help"
            aria-expanded={helpOpen}
            onClick={() => setHelpOpen((o) => !o)}
          >
            <HelpCircle size={15} />
          </button>
          {helpOpen && (
            <div className="tl-help-pop" role="note">
              <h4>Search syntax</h4>
              <dl>
                <dt>term</dt>
                <dd>match anywhere</dd>
                <dt>+term</dt>
                <dd>must contain</dd>
                <dt>-term</dt>
                <dd>must not contain</dd>
                <dt>"a phrase"</dt>
                <dd>exact phrase</dd>
                <dt>column:value</dt>
                <dd>match a specific column</dd>
              </dl>
            </div>
          )}
        </form>
        <label className="tl-field-label">
          Date range
          <select
            className="select"
            value={filters.range}
            onChange={(e) =>
              onChange({ range: e.target.value || null, from: null, to: null })
            }
          >
            {RANGE_PRESETS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
          </select>
        </label>
        <label className="tl-field-label">
          From (UTC)
          <input
            type="datetime-local"
            className="input"
            value={unixToLocalInput(filters.from)}
            onChange={(e) =>
              onChange({ from: localInputToUnix(e.target.value), range: null })
            }
          />
        </label>
        <label className="tl-field-label">
          To (UTC)
          <input
            type="datetime-local"
            className="input"
            value={unixToLocalInput(filters.to)}
            onChange={(e) =>
              onChange({ to: localInputToUnix(e.target.value), range: null })
            }
          />
        </label>
      </div>
      <div className="tl-toolbar-row">
        <div className="tl-modules-wrap">
          <button
            className="btn"
            aria-expanded={modulesOpen}
            onClick={() => setModulesOpen((o) => !o)}
          >
            Modules
            {filters.modules.length > 0 && ` (${filters.modules.length})`}
          </button>
          {modulesOpen && (
            <div className="tl-modules-pop">
              {moduleNames.length === 0 && (
                <div className="tl-col-desc">No modules</div>
              )}
              {moduleNames.map((name) => (
                <label key={name} className="tl-module-option">
                  <input
                    type="checkbox"
                    checked={filters.modules.includes(name)}
                    onChange={(e) => toggleModule(name, e.target.checked)}
                  />
                  {name}
                  <span className="tl-module-count">
                    {moduleCounts?.[name]}
                  </span>
                </label>
              ))}
            </div>
          )}
        </div>
        <label className="tl-check-label">
          <input
            type="checkbox"
            checked={filters.taggedOnly}
            onChange={(e) =>
              onChange({ tagged_only: e.target.checked ? 'true' : null })
            }
          />
          Tagged only
        </label>
        <label className="tl-field-label">
          Analysis
          <select
            className="select"
            value={analysisFilter}
            aria-label="Analysis filter (loaded page only)"
            title="Filters only the events loaded on this page"
            onChange={(e) =>
              onAnalysisFilterChange(e.target.value as AnalysisFilter)
            }
          >
            <option value="all">All events</option>
            <option value="fn">$FN timestamps</option>
            <option value="timestomp">Timestomp suspected</option>
          </select>
        </label>
        <label className="tl-field-label">
          Page size
          <select
            className="select"
            value={String(filters.pageSize)}
            onChange={(e) => onChange({ page_size: e.target.value })}
          >
            {PAGE_SIZES.map((size) => (
              <option key={size} value={String(size)}>
                {size}
              </option>
            ))}
          </select>
        </label>
        <button className="btn" onClick={onOpenColumns}>
          Columns
        </button>
        <div className="tl-spacer" />
        <button
          className="btn"
          disabled={exporting === 'json'}
          onClick={() => onExport('json')}
        >
          {exporting === 'json' ? 'Exporting…' : 'Export JSON'}
        </button>
        <button
          className="btn"
          disabled={exporting === 'csv'}
          onClick={() => onExport('csv')}
        >
          {exporting === 'csv' ? 'Exporting…' : 'Export CSV'}
        </button>
        <button
          className="btn"
          disabled={exporting === 'pdf'}
          onClick={() => onExport('pdf')}
        >
          {exporting === 'pdf' ? 'Exporting…' : 'Export PDF'}
        </button>
        <button
          className="btn"
          disabled={exporting === 'sqlite'}
          onClick={() => onExport('sqlite')}
          title="MemProcFS-Analyzer / Timeline Explorer compatible SQLite database"
        >
          {exporting === 'sqlite' ? 'Exporting…' : 'Export SQLite'}
        </button>
        <button
          className="btn"
          disabled={exporting === 'body_events'}
          onClick={() => onExport('body_events')}
          title="The events shown (memory events included) as a Sleuth Kit body file for mactime; the file list is on the Files page"
        >
          {exporting === 'body_events' ? 'Exporting…' : 'Export body file'}
        </button>
        {totalCount != null && (
          <span className="tl-count">
            {formatCount(totalCount)} events
          </span>
        )}
      </div>
    </div>
  )
}
