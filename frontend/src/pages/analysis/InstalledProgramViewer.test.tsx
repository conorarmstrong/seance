import { render, screen, within } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import type { ParsedRecord } from './api'
import { MISSING, humanizeType } from './lib'
import { RecordsViewerPage } from './RecordsViewerPage'
import { VIEWERS } from './viewers'

/**
 * The InstalledProgram table: one row per Uninstall subkey out of SOFTWARE
 * (machine-wide, native and Wow6432Node) and NTUSER (per-user).
 *
 * What these tests are for, beyond "it renders": an installed-programs list is
 * where a remote-access tool or a wiper is found, and the ways one hides are
 * a GUID-named key with no DisplayName that gets read as "no name, skip it",
 * an InstallDate the registry never held that gets shown as a real date, and a
 * hive whose pending transactions were never applied so the list is the
 * on-disk state and not the last one. Each of those is pinned here.
 */

const CASE_ID = 'case-1'

function program(id: string, metadata: Record<string, unknown>): ParsedRecord {
  return {
    id,
    parent_id: 'hive-1',
    artifact_type: 'ParsedRecord',
    metadata: { type: 'InstalledProgram', ...metadata },
  }
}

/** The common tail every record carries: a clean hive, no replay needed. */
const CLEAN_HIVE = {
  hive_type: 'SOFTWARE',
  source_path: 'C:\\Windows\\System32\\config\\SOFTWARE',
  // The hive's compact replay stamp, nested as the registry parser writes it
  // (the same shape UsbDevice carries) — not flattened to the top level.
  replay: { recovered: false, hive_dirty: false, reason: 'clean' },
}

/** A named, dated, sized application: the ordinary row. */
const CHROME = program('p-chrome', {
  ...CLEAN_HIVE,
  display_name: 'Google Chrome',
  key_name: 'Google Chrome',
  display_version: '120.0.6099.130',
  publisher: 'Google LLC',
  install_location: 'C:\\Program Files\\Google\\Chrome\\Application',
  install_source: null,
  uninstall_string: '"C:\\Program Files\\Google\\Chrome\\Application\\120.0.6099.130\\Installer\\setup.exe" --uninstall',
  install_date: '2024-03-15',
  install_date_source: 'InstallDate',
  estimated_size_kb: 102400,
  system_component: false,
  wow64: false,
  scope: 'machine',
  key_path:
    'Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome',
  key_last_written: '2024-03-15T10:22:31Z',
})

/**
 * A GUID-keyed system component under Wow6432Node with no DisplayName, no
 * InstallDate and no EstimatedSize: the row that is only its key name.
 */
const GUID_ONLY = program('p-guid', {
  ...CLEAN_HIVE,
  display_name: null,
  key_name: '{1D8E6291-B0D5-35EC-8441-6616F567A0F7}',
  display_version: '10.0.40219',
  publisher: 'Microsoft Corporation',
  install_location: null,
  install_source: null,
  uninstall_string: 'MsiExec.exe /X{1D8E6291-B0D5-35EC-8441-6616F567A0F7}',
  install_date: null,
  install_date_source: null,
  estimated_size_kb: null,
  system_component: true,
  wow64: true,
  scope: 'machine',
  key_path:
    'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{1D8E6291-B0D5-35EC-8441-6616F567A0F7}',
  key_last_written: null,
})

/** A per-user install read from an NTUSER hive that was dirty and NOT replayed. */
const STALE_USER_APP = program('p-discord', {
  display_name: 'Discord',
  key_name: 'Discord',
  display_version: '1.0.9030',
  publisher: 'Discord Inc.',
  install_location: 'C:\\Users\\alice\\AppData\\Local\\Discord',
  install_source: null,
  uninstall_string: null,
  install_date: '2024-05-01',
  install_date_source: 'InstallDate',
  estimated_size_kb: 250000,
  system_component: false,
  wow64: false,
  scope: 'user',
  hive_type: 'NTUSER',
  source_path: 'C:\\Users\\alice\\NTUSER.DAT',
  key_path: 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Discord',
  key_last_written: '2024-05-01T08:00:00Z',
  replay: { recovered: false, hive_dirty: true, reason: 'sequence_gap' },
})

/** A per-user install from a hive that was dirty but whose logs WERE applied. */
const REPLAYED_USER_APP = program('p-vscode', {
  display_name: 'Microsoft Visual Studio Code (User)',
  key_name: '{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1',
  display_version: '1.92.0',
  publisher: 'Microsoft Corporation',
  install_location: 'C:\\Users\\alice\\AppData\\Local\\Programs\\Microsoft VS Code',
  install_source: null,
  uninstall_string: null,
  install_date: '2024-08-02',
  install_date_source: 'InstallDate',
  estimated_size_kb: 380000,
  system_component: false,
  wow64: false,
  scope: 'user',
  hive_type: 'NTUSER',
  source_path: 'C:\\Users\\alice\\NTUSER.DAT',
  key_path:
    'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1',
  key_last_written: '2024-08-02T09:30:00Z',
  replay: { recovered: true, hive_dirty: true, reason: 'recovered' },
})

/**
 * Serve `records` as the whole InstalledProgram population and mount the page
 * the viewer is reached through. The viewer is a rich one — it fetches its own
 * pages so it can sort and filter server-side — so it is exercised the way an
 * examiner meets it rather than handed rows it would never receive that way.
 */
async function renderPrograms(records: ParsedRecord[]) {
  const def = VIEWERS['InstalledProgram']
  expect(def, 'InstalledProgram has no tailored viewer').toBeDefined()
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
      const url = new URL(request.url)
      const page = Number(url.searchParams.get('page') ?? 1)
      const pageSize = Number(url.searchParams.get('page_size') ?? 50)
      const start = (page - 1) * pageSize
      return HttpResponse.json({
        records: records.slice(start, start + pageSize),
        total: records.length,
        page,
        page_size: pageSize,
        type: 'InstalledProgram',
      })
    }),
  )
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/analysis/InstalledProgram`]}>
        <Routes>
          <Route path="/cases/:caseId/analysis/:type" element={<RecordsViewerPage />} />
          <Route path="/cases/:caseId/artifacts/:artifactId" element={<div>artifact page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  // The page title is the curated label, so this also fails if the type falls
  // through to the PascalCase splitter ("Installed Program").
  await screen.findByRole('heading', { name: 'Installed programs' }, { timeout: 5000 })
  await screen.findAllByRole('row', undefined, { timeout: 5000 })
}

/** The record table alone: the rich shell also draws the same values in its
 * frequency bars, and a row lookup must not land on one of those. */
function table(): HTMLElement {
  const t = document.querySelector<HTMLElement>('.rv-table')
  if (!t) throw new Error('the rich record table is not on the page')
  return t
}

/** The frequency-bar area, where a dimension label is looked for. */
function dims(): HTMLElement {
  const d = document.querySelector<HTMLElement>('.rv-dims')
  if (!d) throw new Error('the frequency bars are not on the page')
  return d
}

/** The column headings in order, trimmed of their sort indicator. */
function headings(): string[] {
  return within(table())
    .getAllByRole('columnheader')
    .map((h) => (h.textContent ?? '').replace(/[▲▼]/g, '').trim())
}

/** The cell of `row` under the column headed `header`, found by heading
 * rather than by index so the leading marker column cannot shift every test. */
function cellUnder(row: HTMLElement, header: string): HTMLElement {
  const heads = headings()
  const idx = heads.indexOf(header)
  if (idx < 0) throw new Error(`no column headed "${header}" (have ${heads.join(', ')})`)
  return within(row).getAllByRole('cell')[idx]
}

function rowWith(text: string): HTMLElement {
  const cell = within(table()).getByText(text)
  const row = cell.closest('tr')
  if (!row) throw new Error(`"${text}" is not inside a table row`)
  return row
}

describe('InstalledProgram viewer', () => {
  it('lays a program out as name, version, publisher, install date, size, location, scope and hive', async () => {
    await renderPrograms([CHROME])

    // The rich table leads with the notable-row marker column, which has no
    // heading; the named columns follow in this order.
    expect(headings().filter((h) => h !== '')).toEqual([
      'Name',
      'Version',
      'Publisher',
      'Installed',
      'Size',
      'Location',
      'Scope',
      'Hive',
      'Artifact',
    ])

    const row = rowWith('Google Chrome')
    expect(within(row).getByText('120.0.6099.130')).toBeInTheDocument()
    expect(within(row).getByText('Google LLC')).toBeInTheDocument()
    // The registry holds a day, not an instant: the date is shown as the day
    // it is, never widened to "00:00:00 UTC".
    expect(cellUnder(row, 'Installed')).toHaveTextContent('2024-03-15')
    expect(row.textContent).not.toContain('00:00:00')
    // EstimatedSize is in KiB; 102400 KiB is 100 MiB, not "102400 B".
    expect(cellUnder(row, 'Size')).toHaveTextContent('100.0 MiB')
    expect(cellUnder(row, 'Location')).toHaveTextContent(
      'C:\\Program Files\\Google\\Chrome\\Application',
    )
    expect(cellUnder(row, 'Scope')).toHaveTextContent('machine')
    expect(cellUnder(row, 'Hive')).toHaveTextContent('SOFTWARE')
  })

  it('names a program that has no DisplayName by its registry key, and says that is what it is', async () => {
    // A GUID-keyed entry with no DisplayName is the shape a quietly installed
    // MSI leaves. Dropping the row, or printing the placeholder, reads as
    // "nothing there"; printing the GUID as if it were the name reads as a
    // product called that. The key is shown, and marked as the key.
    await renderPrograms([GUID_ONLY, CHROME])

    const key = within(table()).getByText('{1D8E6291-B0D5-35EC-8441-6616F567A0F7}')
    expect(key).toHaveClass('mono')
    expect(key.title).toMatch(/key name/i)
    expect(key.title).toMatch(/DisplayName/)
    const row = key.closest('tr')!
    // A visible marker too: a title alone is invisible until hovered.
    expect(within(cellUnder(row, 'Name')).getByText(/key name/i)).toBeInTheDocument()

    // A named row carries neither.
    const chrome = cellUnder(rowWith('Google Chrome'), 'Name')
    expect(within(chrome).queryByText(/key name/i)).not.toBeInTheDocument()
    expect(within(chrome).getByText('Google Chrome').title).toBe('')
  })

  it('shows an entry with no InstallDate as missing, never as the epoch or an invalid date', async () => {
    await renderPrograms([GUID_ONLY])

    const row = rowWith('{1D8E6291-B0D5-35EC-8441-6616F567A0F7}')
    expect(cellUnder(row, 'Installed')).toHaveTextContent(MISSING)
    expect(cellUnder(row, 'Size')).toHaveTextContent(MISSING)
    expect(row.textContent).not.toContain('1970')
    expect(row.textContent).not.toContain('Invalid Date')
    expect(row.textContent).not.toContain('NaN')
  })

  it('splits the architecture bars into the Wow6432Node view and the native one by that name', async () => {
    // "wow64: true" means the key was read under Wow6432Node — a 32-bit
    // program on a 64-bit Windows — and an examiner who has to know which view
    // a key came from should not have to decode a boolean to find out.
    await renderPrograms([CHROME, GUID_ONLY])

    const bars = dims()
    expect(within(bars).getByText('Architecture')).toBeInTheDocument()
    expect(within(bars).getByText('32-bit (Wow6432Node)')).toBeInTheDocument()
    expect(within(bars).getByText('native')).toBeInTheDocument()
  })

  it('buckets the install month from the date and names the publisher, so the bars are things to click on', async () => {
    await renderPrograms([CHROME, GUID_ONLY, STALE_USER_APP])

    const bars = dims()
    expect(within(bars).getByText('2024-03')).toBeInTheDocument()
    expect(within(bars).getByText('2024-05')).toBeInTheDocument()
    expect(within(bars).getByText('Google LLC')).toBeInTheDocument()
  })

  it('counts machine-wide against per-user installs, and system components against applications', async () => {
    await renderPrograms([CHROME, GUID_ONLY, STALE_USER_APP])

    const stats = document.querySelector<HTMLElement>('.rv-stats')
    expect(stats, 'no stat tiles').not.toBeNull()
    const tile = (label: string) =>
      within(stats!).getByText(label).closest('button')!
    expect(tile('Machine-wide')).toHaveTextContent('2')
    expect(tile('Per-user')).toHaveTextContent('1')
    // The second split is a bar list rather than a second pair of tiles: the
    // shell's tile filter is one partition per viewer, and a tile that
    // highlighted but did not filter would be a control that lies.
    const bars = dims()
    expect(within(bars).getByText('System components')).toBeInTheDocument()
    expect(within(bars).getByText('Applications')).toBeInTheDocument()
  })

  it('marks a row from a dirty hive whose logs were not replayed, and only that row', async () => {
    await renderPrograms([CHROME, GUID_ONLY, STALE_USER_APP, REPLAYED_USER_APP])

    // The stale row: its hive had pending transactions that were never
    // applied, so this entry is the on-disk state and may not be the last one.
    const stale = rowWith('Discord')
    expect(stale).toHaveClass('rv-notable')
    const marker = within(stale).getByTitle(/dirty/i)
    expect(marker.title).toMatch(/not (applied|replayed)/i)
    expect(marker.title).toContain('sequence_gap')

    // A replayed hive is the recovered state: nothing to flag.
    const replayed = rowWith('Microsoft Visual Studio Code (User)')
    expect(replayed).not.toHaveClass('rv-notable')
    expect(within(replayed).queryByTitle(/dirty/i)).not.toBeInTheDocument()

    // A system component is ordinary, not suspicious: it is NOT notable.
    const sys = rowWith('{1D8E6291-B0D5-35EC-8441-6616F567A0F7}')
    expect(sys).not.toHaveClass('rv-notable')

    const clean = rowWith('Google Chrome')
    expect(clean).not.toHaveClass('rv-notable')
  })

  it('asks the server to order by install date and size, newest and biggest first, and never by the composed name', async () => {
    // "What was installed last" and "what is biggest" have to be answered
    // over the whole record type, not the page that happens to be loaded, so
    // the columns name the server key rather than sorting in the browser.
    const columns = VIEWERS['InstalledProgram']?.columns ?? []
    const byKey = new Map(columns.map((c) => [c.key, c]))
    expect(byKey.get('install_date')?.sortKey).toBe('install_date')
    expect(byKey.get('install_date')?.sortDefaultOrder).toBe('desc')
    expect(byKey.get('estimated_size_kb')?.sortKey).toBe('estimated_size_kb')
    expect(byKey.get('estimated_size_kb')?.sortDefaultOrder).toBe('desc')
    // The name cell falls back to the key name, so no one key orders it the
    // way its heading reads; it offers no sort rather than a wrong one.
    expect(byKey.get('display_name')?.sortKey).toBeUndefined()
    // Version strings order lexically on the server ("10.0" before "9.0"),
    // which is not the order the heading promises.
    expect(byKey.get('display_version')?.sortKey).toBeUndefined()
  })
})

describe('installed program record label', () => {
  it('labels the type "Installed programs" rather than the PascalCase splitter\'s singular', () => {
    expect(humanizeType('InstalledProgram')).toBe('Installed programs')
  })
})
