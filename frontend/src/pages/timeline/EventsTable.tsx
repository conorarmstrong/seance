import { memo, useCallback, useRef, useState } from 'react'
import type { KeyboardEvent } from 'react'
import { Link } from 'react-router-dom'
import { Star } from 'lucide-react'
import type { TimelineEvent, VirtualColumnDef } from '../../api/types'
import { useRovingRows } from '../../hooks/useRovingRows'
import { formatUtc } from '../../lib/format'
import { pivotTarget } from '../../lib/pivotable'
import { PivotMono } from '../analysis/cells'
import { isFnEvent, siFnPairs, timestompHint } from './analysis'

function prettyDetails(details: string): string {
  try {
    return JSON.stringify(JSON.parse(details), null, 2)
  } catch {
    return details
  }
}

/**
 * Resolve a virtual column for one event, in the column's source order.
 *
 * A source naming `source_modules` only answers for events from those modules.
 * Without that gate the first non-null path wins whatever produced the row, so
 * a source written for one artifact answers for another — a registry event
 * taking its Resource Path from a filename, say, which is a claim about the
 * evidence rather than a display quirk.
 *
 * `source_modules` is matched by equality against the full module id, because
 * that is what an event carries. The older `artifact_types` is not consulted:
 * its vocabulary ("registry", "ntfs.mft") appears nowhere in an event, so
 * gating on it would blank every typed source. See `VirtualColumnSource`.
 */
/**
 * Resolve a virtual column for one event, keeping the `full_details` key that
 * produced the value.
 *
 * The key is what decides whether the value is an identifier worth a pivot
 * (§1.0): a virtual column over `$.client_ip` extracts an address, one over
 * `$.bytes_total` extracts a count, and only the first is something an
 * examiner follows across the case. Returning the key means the cell asks the
 * same `pivotTarget` question the artifact inspector does, so one rule governs
 * both surfaces.
 */
function dynamicResolved(
  event: TimelineEvent,
  column: VirtualColumnDef,
): { key: string; value: string } | null {
  for (const source of column.sources) {
    const modules = source.source_modules ?? []
    if (modules.length > 0 && !modules.includes(event.source_module)) continue
    const key = source.path.replace(/^\$\./, '')
    const value = event.dynamic_fields?.[key]
    if (value !== undefined && value !== null) {
      return {
        key,
        value: typeof value === 'object' ? JSON.stringify(value) : String(value),
      }
    }
  }
  return null
}

/**
 * The keyboard contract handed to every row, held stable for the life of the
 * table.
 *
 * `useRovingRows` hands out a fresh props object per row per render, which a
 * memoized row cannot take without re-rendering every row on every keystroke —
 * and the memoization here is load-bearing: a page carries up to 500 events,
 * each with a checkbox, a star and a note button. Passing these three stable
 * callbacks plus the row's index and a plain `active` boolean means only the
 * two rows whose active flag actually flipped re-render when the examiner
 * arrows down a page.
 */
interface RowKeyboard {
  register: (index: number, el: HTMLElement | null) => void
  onFocus: (index: number) => void
  onKeyDown: (index: number, event: KeyboardEvent<HTMLElement>) => void
}

export function EventsTable({
  events,
  caseId,
  columns,
  sortBy,
  sortOrder,
  selectedIds,
  onSort,
  onToggleTag,
  onEditNote,
  onToggleSelect,
  onToggleSelectAll,
}: {
  events: TimelineEvent[]
  caseId: string
  columns: VirtualColumnDef[]
  sortBy: string
  sortOrder: string
  selectedIds: Set<string>
  onSort: (field: string) => void
  onToggleTag: (event: TimelineEvent) => void
  onEditNote: (event: TimelineEvent) => void
  onToggleSelect: (eventId: string, selected: boolean) => void
  onToggleSelectAll: (selected: boolean) => void
}) {
  const [expandedId, setExpandedId] = useState<string | null>(null)

  // Stable across renders so a memoized RowPair only re-renders when its own
  // event/selected/expanded changes, not on every unrelated selection toggle.
  const handleExpand = useCallback((id: string) => {
    setExpandedId((cur) => (cur === id ? null : id))
  }, [])

  // The table is a single tab stop on the shared roving-tabindex primitive,
  // rather than one stop per row plus one per control inside it. Arrowing
  // moves real DOM focus, so a screen reader reads out the event arrived at,
  // and the hook scrolls it into view — a page of 500 events is many screens
  // tall and a selection below the fold is one the examiner cannot read.
  //
  // Detail rows need no special handling any more: the hook addresses rows by
  // index through refs the event rows register, so an open detail row is not a
  // thing the arrows can land on. That is what the old sibling-walk was for.
  const eventsRef = useRef(events)
  eventsRef.current = events
  const roving = useRovingRows({
    count: events.length,
    onActivate: (index) => {
      const event = eventsRef.current[index]
      if (event) handleExpand(event.id)
    },
  })
  const rovingRef = useRef(roving)
  rovingRef.current = roving

  // Everything the examiner can do to a row, from the row.
  //
  // The checkbox, the star and the note button are out of the tab order
  // (`tabIndex={-1}`), because a control inside a row is a tab stop inside a
  // row: three of them across a 500-event page is the same wall of presses the
  // roving stop was introduced to pull down, and it makes no difference that
  // the row itself is a single stop. They stay clickable, and each one has a
  // key on the focused row instead — Space selects, `t` tags, `n` edits the
  // note of an event that carries one. The keys are named in each control's
  // tooltip so the pairing is discoverable from the row rather than only from
  // the help page.
  const handlers = useRef({ onToggleTag, onEditNote, onToggleSelect })
  handlers.current = { onToggleTag, onEditNote, onToggleSelect }
  const selectedRef = useRef(selectedIds)
  selectedRef.current = selectedIds

  const keyboard = useRef<RowKeyboard>({
    register: (index, el) => rovingRef.current.getRowProps(index).ref(el),
    onFocus: (index) => rovingRef.current.getRowProps(index).onFocus(),
    onKeyDown: (index, event) => {
      // Only keys aimed at the row itself. A key pressed while focus is inside
      // one of the row's controls belongs to that control.
      if (event.target !== event.currentTarget) return
      const item = eventsRef.current[index]
      if (item) {
        switch (event.key) {
          case ' ':
            // Space selects, the way a row checkbox does everywhere else — and
            // it must swallow the key, or the page scrolls under the examiner.
            event.preventDefault()
            handlers.current.onToggleSelect(
              item.id,
              !selectedRef.current.has(item.id),
            )
            return
          case 't':
          case 'T':
            event.preventDefault()
            handlers.current.onToggleTag(item)
            return
          case 'n':
          case 'N':
            // Only where the button is: a note belongs to a tag, and offering
            // the key on an untagged event would open an editor for a note
            // that has nothing to attach to.
            if (item.is_tagged !== true) return
            event.preventDefault()
            handlers.current.onEditNote(item)
            return
        }
      }
      rovingRef.current.getRowProps(index).onKeyDown(event)
    },
  }).current

  const sortIndicator =
    sortBy === 'timestamp' ? (sortOrder === 'asc' ? ' ▲' : ' ▼') : ''

  const allSelected =
    events.length > 0 && events.every((e) => selectedIds.has(e.id))
  const someSelected = events.some((e) => selectedIds.has(e.id))

  return (
    <div className="tl-table-wrap">
      <table className="data-table tl-table">
        <thead>
          <tr>
            <th className="tl-check-col">
              <input
                type="checkbox"
                aria-label="Select all events on page"
                checked={allSelected}
                ref={(el) => {
                  if (el) el.indeterminate = !allSelected && someSelected
                }}
                onChange={(e) => onToggleSelectAll(e.target.checked)}
              />
            </th>
            <th className="tl-star-col" aria-label="Tagged"></th>
            <th>
              <button className="tl-sort" onClick={() => onSort('timestamp')}>
                Timestamp{sortIndicator}
              </button>
            </th>
            <th>Event Type</th>
            <th>Module</th>
            <th>Description</th>
            {columns.map((col) => (
              <th key={col.id}>{col.name}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {events.map((event, index) => (
            <RowPair
              key={event.id}
              event={event}
              caseId={caseId}
              columns={columns}
              index={index}
              active={index === roving.activeIndex}
              keyboard={keyboard}
              expanded={expandedId === event.id}
              selected={selectedIds.has(event.id)}
              onExpand={handleExpand}
              onToggleTag={onToggleTag}
              onEditNote={onEditNote}
              onToggleSelect={onToggleSelect}
            />
          ))}
        </tbody>
      </table>
    </div>
  )
}

const RowPair = memo(function RowPair({
  event,
  caseId,
  columns,
  index,
  active,
  keyboard,
  expanded,
  selected,
  onExpand,
  onToggleTag,
  onEditNote,
  onToggleSelect,
}: {
  event: TimelineEvent
  caseId: string
  columns: VirtualColumnDef[]
  index: number
  active: boolean
  keyboard: RowKeyboard
  expanded: boolean
  selected: boolean
  onExpand: (id: string) => void
  onToggleTag: (event: TimelineEvent) => void
  onEditNote: (event: TimelineEvent) => void
  onToggleSelect: (eventId: string, selected: boolean) => void
}) {
  const tagged = event.is_tagged === true
  const fn = isFnEvent(event)
  const stomp = timestompHint(event)
  const pairs = expanded ? siFnPairs(event) : null

  return (
    <>
      <tr
        className={expanded ? 'selected' : ''}
        onClick={() => onExpand(event.id)}
        ref={(el) => keyboard.register(index, el)}
        tabIndex={active ? 0 : -1}
        data-active={active ? 'true' : undefined}
        onFocus={() => keyboard.onFocus(index)}
        onKeyDown={(e) => keyboard.onKeyDown(index, e)}
        aria-expanded={expanded}
      >
        <td className="tl-check-col">
          <input
            type="checkbox"
            aria-label={`Select event ${event.short_desc}`}
            title="Select (Space)"
            tabIndex={-1}
            checked={selected}
            onClick={(e) => e.stopPropagation()}
            onChange={(e) => onToggleSelect(event.id, e.target.checked)}
          />
        </td>
        <td className="tl-star-col">
          <button
            className={`tl-star${tagged ? ' tagged' : ''}`}
            aria-label={tagged ? 'Remove tag' : 'Tag event'}
            title={tagged ? 'Remove tag (t)' : 'Tag event (t)'}
            tabIndex={-1}
            onClick={(e) => {
              e.stopPropagation()
              onToggleTag(event)
            }}
          >
            <Star size={15} fill={tagged ? 'currentColor' : 'none'} />
          </button>
        </td>
        <td className="mono tl-ts">
          {formatUtc(new Date(event.timestamp * 1000).toISOString())}
        </td>
        <td className="tl-event-type">
          {event.timestamp_desc}
          {fn && (
            <span
              className="tl-fn-tag"
              title="Derived from the $FILE_NAME attribute"
            >
              $FN
            </span>
          )}
          {stomp && (
            <span
              className="tl-timestomp badge badge-danger"
              title={
                stomp.reasons.length > 0
                  ? stomp.reasons.join('\n')
                  : 'Timestomp suspected'
              }
              aria-label={
                stomp.reasons.length > 0
                  ? `Timestomp suspected: ${stomp.reasons.join('; ')}`
                  : 'Timestomp suspected'
              }
            >
              Timestomp
            </span>
          )}
        </td>
        <td>
          <span className="badge">{event.source_module}</span>
        </td>
        <td className="tl-desc">
          {event.short_desc}
          {tagged && (
            <>
              {event.tag_note && (
                <span className="tl-note" title={event.tag_note}>
                  {event.tag_note}
                </span>
              )}
              <button
                className="link-button tl-note-btn"
                title={event.tag_note ? 'Edit note (n)' : 'Add note (n)'}
                tabIndex={-1}
                onClick={(e) => {
                  e.stopPropagation()
                  onEditNote(event)
                }}
              >
                {event.tag_note ? 'Edit note' : 'Add note'}
              </button>
            </>
          )}
        </td>
        {columns.map((col) => {
          const resolved = dynamicResolved(event, col)
          const pivot = resolved
            ? pivotTarget(resolved.key, resolved.value)
            : null
          return (
            <td key={col.id} className="mono">
              {pivot !== null ? (
                <PivotMono pivotOn={pivot} />
              ) : (
                (resolved?.value ?? '')
              )}
            </td>
          )
        })}
      </tr>
      {expanded && (
        <tr className="tl-detail-row" onClick={(e) => e.stopPropagation()}>
          <td colSpan={6 + columns.length}>
            {stomp && (
              <div className="tl-timestomp-reasons">
                <strong>Timestomp suspected</strong>
                {stomp.reasons.length > 0 && (
                  <ul>
                    {stomp.reasons.map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}
            {pairs && (
              <table className="tl-sifn">
                <caption>$STANDARD_INFORMATION vs $FILE_NAME</caption>
                <thead>
                  <tr>
                    <th />
                    <th>$SI</th>
                    <th>$FN</th>
                  </tr>
                </thead>
                <tbody>
                  {pairs.map((pair) => (
                    <tr key={pair.label}>
                      <th scope="row">{pair.label}</th>
                      <td className="mono">{pair.si ? formatUtc(pair.si) : '—'}</td>
                      <td className="mono">{pair.fn ? formatUtc(pair.fn) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <pre className="tl-details mono">
              {prettyDetails(event.full_details)}
            </pre>
            <Link to={`/cases/${caseId}/artifacts/${event.artifact_id}`}>
              View artifact
            </Link>
          </td>
        </tr>
      )}
    </>
  )
})
