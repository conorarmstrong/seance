import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { formatUtc } from '../../lib/format'
import { valueToEpochMs } from '../../lib/epoch'
import { usePivot } from '../../app/PivotContext'
import { MISSING, metaFirst } from './lib'
import type { ParsedRecord, RecordMetadata } from './api'

/** A monospace value that truncates with the full text in a tooltip. */
export function MonoTrunc({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="mono">{MISSING}</span>
  return (
    <span className="mono an-trunc" title={value}>
      {value}
    </span>
  )
}

/**
 * A monospace value that is also a pivot trigger: clicking it opens the
 * universal pivot on `pivotOn` (the identifier), showing every artifact in
 * the case that references it grouped by record kind. `display` is what the
 * cell shows (e.g. `10.0.0.5:443`); the pivot is on the bare identifier
 * (`10.0.0.5`). This is how a C2 address in a flow row becomes one click from
 * its whole footprint across the case.
 */
export function PivotMono({
  pivotOn,
  display,
}: {
  pivotOn: string | null | undefined
  display?: string | null | undefined
}) {
  const { openPivot } = usePivot()
  const shown = display ?? pivotOn
  if (!pivotOn || !shown) return <span className="mono">{MISSING}</span>
  return (
    <button
      type="button"
      className="mono an-trunc an-pivot-cell"
      title={`Pivot on ${pivotOn} — show every artifact that references it`}
      onClick={() => openPivot(pivotOn)}
    >
      {shown}
    </button>
  )
}

/**
 * A participant's name in a conversation, as a pivot trigger (§5.1).
 *
 * The bubble shows the resolved contact name; the pivot is on the raw handle —
 * the phone number, JID or address the chat database actually stored — because
 * that is the identifier the rest of the case carries. Clicking a name in a
 * thread is how "who else did this person talk to, and what else touches this
 * number" gets asked without retyping it into search.
 *
 * `className` is the caller's, so a chat bubble keeps its own styling rather
 * than inheriting a table cell's. When there is nothing to pivot on (a message
 * of mine, an unattributed sender) it renders the label as plain text: an
 * affordance that leads nowhere is worse than none.
 */
export function PivotName({
  pivotOn,
  label,
  className,
}: {
  pivotOn: string | null | undefined
  label: string
  className?: string
}) {
  const { openPivot } = usePivot()
  const target = pivotOn?.trim()
  if (!target) return <span className={className}>{label}</span>
  return (
    <button
      type="button"
      className={className ? `${className} an-pivot-name` : 'an-pivot-name'}
      title={`Pivot on ${target} — show every artifact that references it`}
      onClick={() => openPivot(target)}
    >
      {label}
    </button>
  )
}

/**
 * Several identifiers in one cell, each its own pivot trigger.
 *
 * A DNS query answered with two A records holds two addresses, and joining
 * them into `"1.2.3.4, 5.6.7.8"` makes the cell one unpivotable string —
 * the examiner can see both and follow neither. Each value here is a separate
 * trigger, so either address is one click from its footprint across the case.
 * An empty list renders the em dash, never an empty cell.
 */
export function PivotList({
  values,
}: {
  values: readonly (string | null | undefined)[] | null | undefined
}) {
  const present = (values ?? []).filter(
    (v): v is string => typeof v === 'string' && v.trim() !== '',
  )
  if (present.length === 0) return <span className="mono">{MISSING}</span>
  return (
    <span className="an-pivot-list">
      {present.map((v, i) => (
        <span key={`${v}-${i}`}>
          {i > 0 && <span aria-hidden="true">, </span>}
          <PivotMono pivotOn={v} />
        </span>
      ))}
    </span>
  )
}

/** Plain metadata string cell (or em dash). */
export function Val({ value }: { value: string | null | undefined }) {
  return <>{value && value.length ? value : MISSING}</>
}

/**
 * Render the first present timestamp key as a UTC-formatted mono value.
 * Accepts ISO strings; numeric unix seconds are converted.
 */
export function timeCell(meta: RecordMetadata, keys: string[]): ReactNode {
  const raw = metaFirst(meta, keys)
  if (raw == null) return <span className="mono">{MISSING}</span>
  const iso = toIso(raw)
  return <span className="mono">{formatUtc(iso)}</span>
}

/** Coerce a raw metadata timestamp (ISO, unix, or Windows FILETIME) to ISO.
 * Falls back to the raw string when the value is out of range, so a bad or
 * exotic timestamp never throws in `toISOString()` and crashes the table. */
export function toIso(raw: string): string {
  if (/[-:T]/.test(raw)) return raw // already a formatted date string
  const ms = valueToEpochMs(raw)
  return ms == null ? raw : new Date(ms).toISOString()
}

/** Link a record to its artifact detail page. */
export function ArtifactLink({
  caseId,
  id,
  children,
  tabIndex,
}: {
  caseId: string
  id: string
  children: ReactNode
  /**
   * Pass -1 inside a table whose rows are a roving tab stop. A link in every
   * row is a tab stop in every row, which puts the table straight back to one
   * stop per row however the row element itself is set up; the row's Enter
   * key reaches the same artifact, and the link stays clickable.
   */
  tabIndex?: number
}) {
  return (
    <Link to={`/cases/${caseId}/artifacts/${id}`} tabIndex={tabIndex}>
      {children}
    </Link>
  )
}

export interface CellCtx {
  caseId: string
  record: ParsedRecord
}

export interface Column {
  /** Stable id + default header source. */
  key: string
  header: string
  /** Cell renderer given the record metadata and context. */
  render: (meta: RecordMetadata, ctx: CellCtx) => ReactNode
  /**
   * Bare metadata key this column can be ordered by, SERVER-side.
   *
   * Present only where sorting on it is meaningful, and it is the key the
   * server orders on rather than whatever the cell renderer displays: a cell
   * that falls back to a second key when the first is absent will not order the
   * way its heading reads, so `RecordTable` names the key on the sort control
   * instead of letting the heading imply it. A column without one is not
   * sortable, which is the right answer for anything derived in the browser —
   * the ordering has to be something the whole record type can be put in, not
   * just the rows that happen to be loaded.
   */
  sortKey?: string
  /**
   * Which direction this column is wanted in on the FIRST click of its header.
   *
   * Not a guess from the key's name: the helper that built the column knows
   * whether it renders text or a magnitude, and those want opposite things. A
   * name or a path is read A→Z; a time, a count, a size or a flag is being
   * asked "which are the biggest / newest / set ones", and starting those
   * ascending puts the empty rows on top and costs a second click every time.
   * Defaults to ascending.
   */
  sortDefaultOrder?: 'asc' | 'desc'
}
