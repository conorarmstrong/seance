import { act, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useCallback, useState } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { TimelineEvent, VirtualColumnDef } from '../../api/types'
import { EventsTable } from './EventsTable'

// isFnEvent runs exactly once per RowPair render, so counting its calls counts
// how many rows actually rendered. Wrap the real impl so behavior is unchanged.
vi.mock('./analysis', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./analysis')>()
  return { ...actual, isFnEvent: vi.fn(actual.isFnEvent) }
})
import { isFnEvent } from './analysis'
const isFnMock = vi.mocked(isFnEvent)

const NO_COLUMNS: VirtualColumnDef[] = []

function ev(id: string, ts: number): TimelineEvent {
  return {
    id,
    case_id: 'c1',
    artifact_id: `a-${id}`,
    timestamp: ts,
    timestamp_desc: 'File Created',
    source_module: 'mft',
    short_desc: `event ${id}`,
    full_details: '{}',
    is_tagged: false,
  }
}

const EVENTS = [ev('e1', 300), ev('e2', 200), ev('e3', 100)]

// Holds selectedIds so a checkbox toggle is a genuine parent state change,
// with every other EventsTable prop referentially stable across renders.
function Harness() {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const onToggleSelect = useCallback((id: string, selected: boolean) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (selected) next.add(id)
      else next.delete(id)
      return next
    })
  }, [])
  const noop = useCallback(() => {}, [])
  return (
    <MemoryRouter>
      <EventsTable
        events={EVENTS}
        caseId="c1"
        columns={NO_COLUMNS}
        sortBy="timestamp"
        sortOrder="desc"
        selectedIds={selectedIds}
        onSort={noop}
        onToggleTag={noop}
        onEditNote={noop}
        onToggleSelect={onToggleSelect}
        onToggleSelectAll={noop}
      />
    </MemoryRouter>
  )
}

beforeEach(() => {
  isFnMock.mockClear()
})

describe('EventsTable row memoization', () => {
  it('re-renders only the toggled row when selection changes', async () => {
    render(<Harness />)
    // Initial paint renders every row once.
    expect(isFnMock).toHaveBeenCalledTimes(EVENTS.length)
    isFnMock.mockClear()

    await userEvent.click(screen.getByLabelText('Select event event e1'))

    // Only the toggled row re-renders; the other two are memoized away.
    expect(isFnMock).toHaveBeenCalledTimes(1)
  })
})

// ── Virtual column resolution (B8-042) ──────────────────────────────────────

/**
 * A Resource Path column whose sources are in the given order.
 *
 * Order is a parameter because it is the whole point: the gate has to hold when
 * a *foreign* source comes first. A column that happens to list the right
 * source first would pass with the gate removed, which would make the test
 * decoration rather than evidence — it did, until a mutation run caught it.
 */
function resourcePath(order: string[]): VirtualColumnDef {
  const gates: Record<string, string[]> = {
    '$.key_path': ['plugin.windows.registry_parser'],
    '$.filename': ['plugin.ntfs.mft_parser'],
    '$.path': [],
  }
  return {
    id: 'vc_resource_path',
    name: 'Resource Path',
    description: 'File path, registry key, URL, or resource identifier',
    type: 'string',
    sources: order.map((path) => ({
      path,
      artifact_types: [],
      source_modules: gates[path] ?? [],
    })),
    default_visible: true,
    built_in: true,
  }
}

function eventFrom(
  sourceModule: string,
  fields: Record<string, unknown>,
): TimelineEvent {
  return {
    id: `ev-${sourceModule}`,
    case_id: 'c1',
    artifact_id: 'a1',
    timestamp: 100,
    timestamp_desc: 'Registry Key Modified',
    source_module: sourceModule,
    short_desc: 'an event',
    full_details: JSON.stringify(fields),
    is_tagged: false,
    dynamic_fields: fields,
  }
}

function renderWith(events: TimelineEvent[], column: VirtualColumnDef) {
  const noop = () => {}
  return render(
    <MemoryRouter>
      <EventsTable
        events={events}
        caseId="c1"
        columns={[column]}
        sortBy="timestamp"
        sortOrder="desc"
        selectedIds={new Set()}
        onSort={noop}
        onToggleTag={noop}
        onEditNote={noop}
        onToggleSelect={noop}
        onToggleSelectAll={noop}
      />
    </MemoryRouter>,
  )
}

describe('virtual column source gating', () => {
  it('does not resolve a registry event Path from $.filename', () => {
    // The event carries both: a key_path of its own, and a filename that
    // belongs to a different artifact's vocabulary. Ungated, whichever source
    // came first in the list would win regardless of what produced the row —
    // and reporting a filename as a registry key is a claim about the
    // evidence, not a display quirk.
    // $.filename FIRST: without the gate it wins and the registry key is lost.
    renderWith(
      [
        eventFrom('plugin.windows.registry_parser', {
          key_path: 'HKLM\\SOFTWARE\\Look@LAN',
          filename: 'NOT-THE-REGISTRY-KEY.txt',
        }),
      ],
      resourcePath(['$.filename', '$.key_path', '$.path']),
    )

    expect(screen.getByText('HKLM\\SOFTWARE\\Look@LAN')).toBeInTheDocument()
    expect(screen.queryByText('NOT-THE-REGISTRY-KEY.txt')).toBeNull()
  })

  it('does not resolve an MFT event Path from a registry key', () => {
    // The mirror case, so the gate is not merely ordering by luck.
    // $.key_path FIRST, for the same reason in the other direction.
    renderWith(
      [
        eventFrom('plugin.ntfs.mft_parser', {
          key_path: 'HKLM\\NOT-A-FILE',
          filename: 'C:\\Windows\\System32\\cmd.exe',
        }),
      ],
      resourcePath(['$.key_path', '$.filename', '$.path']),
    )

    expect(
      screen.getByText('C:\\Windows\\System32\\cmd.exe'),
    ).toBeInTheDocument()
    expect(screen.queryByText('HKLM\\NOT-A-FILE')).toBeNull()
  })

  it('still resolves an ungated fallback for a module it has never heard of', () => {
    // A source with no source_modules answers for anything. Without this a new
    // plugin's events would render blank rather than falling through.
    renderWith(
      [eventFrom('plugin.some.future_parser', { path: '/srv/evidence/thing' })],
      resourcePath(['$.key_path', '$.filename', '$.path']),
    )

    expect(screen.getByText('/srv/evidence/thing')).toBeInTheDocument()
  })
})

// ── Keyboard navigation ─────────────────────────────────────────────────────

/** The event rows, in document order, without the expanded detail rows. */
function eventRows(): HTMLElement[] {
  return Array.from(
    document.querySelectorAll<HTMLElement>('tbody tr:not(.tl-detail-row)'),
  )
}

describe('EventsTable keyboard navigation', () => {
  it('is one tab stop for the whole table, not one per row', () => {
    render(<Harness />)
    const rows = eventRows()
    expect(rows).toHaveLength(EVENTS.length)
    // A 100-row page of rows each carrying tabIndex=0, each with a checkbox, a
    // star and sometimes a note button, put roughly 400 stops between the
    // filter box and the export button. Exactly one row is tabbable; the
    // arrows do the rest.
    expect(rows.filter((r) => r.getAttribute('tabindex') === '0')).toHaveLength(
      1,
    )
    expect(rows[0]).toHaveAttribute('tabindex', '0')
  })

  it('walks the event rows with the arrows, stepping over an open detail row', async () => {
    render(<Harness />)
    const rows = eventRows()
    act(() => rows[0].focus())

    // Open the first row's details: the detail row is now the next sibling in
    // the DOM, and it is not an event — ArrowDown must land on event two.
    await userEvent.keyboard('{Enter}')
    expect(screen.getByText(/View artifact/)).toBeInTheDocument()

    await userEvent.keyboard('{ArrowDown}')
    expect(eventRows()[1]).toHaveFocus()
    await userEvent.keyboard('{ArrowUp}')
    expect(eventRows()[0]).toHaveFocus()
  })

  it('jumps to the first and last event with Home and End', async () => {
    render(<Harness />)
    act(() => eventRows()[0].focus())
    await userEvent.keyboard('{End}')
    expect(eventRows()[EVENTS.length - 1]).toHaveFocus()
    await userEvent.keyboard('{Home}')
    expect(eventRows()[0]).toHaveFocus()
  })

  it('leaves keys pressed inside a row control to that control', async () => {
    // Enter on the star button tags the event; it must not also expand the
    // row, and the arrows must not steal keys from an inner control either.
    render(<Harness />)
    const star = screen.getAllByLabelText('Tag event')[0]
    act(() => star.focus())
    await userEvent.keyboard('{Enter}')
    expect(screen.queryByText(/View artifact/)).toBeNull()
  })
})

describe('EventsTable row controls do not re-create the tab stops', () => {
  /** Anything inside the rows that Tab would stop on. */
  function tabbableInRows(): HTMLElement[] {
    return Array.from(
      document.querySelectorAll<HTMLElement>(
        'tbody tr:not(.tl-detail-row) a, tbody tr:not(.tl-detail-row) button, tbody tr:not(.tl-detail-row) input',
      ),
    ).filter((el) => el.getAttribute('tabindex') !== '-1')
  }

  it('leaves nothing inside a row in the tab order', () => {
    // A roving tab stop on the row is worth nothing if the checkbox, the star
    // and the note button inside it are each still a stop: 100 rows would put
    // some 300 presses between the filter box and the export button, which is
    // the very cost this table was converted to remove. Every one of them is
    // reachable from the focused row instead — Space selects, t tags, n edits
    // the note — and all three stay clickable.
    render(<Harness />)
    expect(tabbableInRows()).toHaveLength(0)
  })

  it('selects the focused event with Space', async () => {
    render(<Harness />)
    act(() => eventRows()[1].focus())
    await userEvent.keyboard(' ')

    const box = screen.getByLabelText('Select event event e2') as HTMLInputElement
    expect(box.checked).toBe(true)
    // And it does not expand the row: Space and Enter are different verbs.
    expect(screen.queryByText(/View artifact/)).toBeNull()

    await userEvent.keyboard(' ')
    expect(box.checked).toBe(false)
  })

  it('tags the focused event with t and opens its note with n', async () => {
    const onToggleTag = vi.fn()
    const onEditNote = vi.fn()
    render(
      <MemoryRouter>
        <EventsTable
          events={[ev('e1', 300), { ...ev('e2', 200), is_tagged: true }]}
          caseId="c1"
          columns={NO_COLUMNS}
          sortBy="timestamp"
          sortOrder="desc"
          selectedIds={new Set()}
          onSort={() => {}}
          onToggleTag={onToggleTag}
          onEditNote={onEditNote}
          onToggleSelect={() => {}}
          onToggleSelectAll={() => {}}
        />
      </MemoryRouter>,
    )

    act(() => eventRows()[0].focus())
    await userEvent.keyboard('t')
    expect(onToggleTag).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'e1' }),
    )

    // The note button only exists on a tagged event, so neither does the key.
    await userEvent.keyboard('n')
    expect(onEditNote).not.toHaveBeenCalled()

    act(() => eventRows()[1].focus())
    await userEvent.keyboard('n')
    expect(onEditNote).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'e2' }),
    )
  })
})

/**
 * §1.0. A virtual column that extracts an identifier is a pivot trigger, so a
 * C2 address or a file name on the timeline is one click from everything else
 * in the case that touches it. A column that extracts a count is not: the same
 * `pivotTarget` rule governs this surface and the artifact inspector, so an
 * examiner does not have to learn two.
 */
describe('timeline virtual columns as pivot triggers', () => {
  function column(id: string, path: string): VirtualColumnDef {
    return {
      id: `vc_${id}`,
      name: id,
      description: id,
      type: 'string',
      sources: [{ path, artifact_types: [], source_modules: [] }],
      default_visible: true,
      built_in: true,
    }
  }

  it('offers a pivot on an extracted identifier', () => {
    renderWith(
      [eventFrom('plugin.network.pcap_parser', { client_ip: '10.0.0.5' })],
      column('client_ip', '$.client_ip'),
    )
    const cell = screen.getByRole('button', { name: '10.0.0.5' })
    expect(cell).toHaveAttribute(
      'title',
      expect.stringContaining('Pivot on 10.0.0.5'),
    )
  })

  it('does not offer one on an extracted count', () => {
    renderWith(
      [eventFrom('plugin.network.pcap_parser', { bytes_total: '4096' })],
      column('bytes_total', '$.bytes_total'),
    )
    // Shown, but not a trigger: "every artifact referencing 4096" is noise.
    expect(screen.getByText('4096')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '4096' })).toBeNull()
  })

  it('renders an unresolved column as empty rather than a dead trigger', () => {
    renderWith(
      [eventFrom('plugin.network.pcap_parser', {})],
      column('client_ip', '$.client_ip'),
    )
    expect(screen.queryByRole('button', { name: /10\.0\.0\.5/ })).toBeNull()
  })
})
