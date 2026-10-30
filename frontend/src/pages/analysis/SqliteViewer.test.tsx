import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import type { ParsedRecord } from './api'
import { RecordsViewerPage } from './RecordsViewerPage'
import { SqliteViewer } from './SqliteViewer'

const CASE_ID = 'case-1'

function mockRows(rows: ParsedRecord[]) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
      const type = new URL(request.url).searchParams.get('type') ?? ''
      const all = type === 'SqliteRow' ? rows : []
      return HttpResponse.json({
        records: all,
        total: all.length,
        page: 1,
        page_size: 50,
        type,
      })
    }),
  )
}

function row(id: string, cols: Record<string, unknown>): ParsedRecord {
  return {
    id,
    parent_id: `a-${id}`,
    artifact_type: 'ParsedRecord',
    metadata: { type: 'SqliteRow', table: 'messages', rowid: id, columns: cols },
  }
}

function renderViewer() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/analysis/SqliteRow`]}>
        <Routes>
          <Route
            path="/cases/:caseId/analysis/:type"
            element={<RecordsViewerPage />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('SqliteViewer power tools', () => {
  it('decodes a column in place when interpreted as a Unix-seconds timestamp', async () => {
    mockRows([
      row('1', { body: 'hi', ts: 1700000000 }),
      row('2', { body: 'bye', ts: 1700000001 }),
    ])
    renderViewer()

    // Raw value visible first.
    expect(await screen.findByText('1700000000')).toBeInTheDocument()

    // Interpret the `ts` column as Unix seconds.
    await userEvent.selectOptions(
      screen.getByLabelText('Interpret ts as'),
      'Unix (seconds)',
    )
    expect(await screen.findByText('2023-11-14T22:13:20Z')).toBeInTheDocument()
    expect(screen.queryByText('1700000000')).not.toBeInTheDocument()
  })

  it('filters rows by a per-column value', async () => {
    mockRows([
      row('1', { body: 'hello world' }),
      row('2', { body: 'goodbye' }),
    ])
    renderViewer()
    await screen.findByText('hello world')

    await userEvent.type(screen.getByLabelText('Filter body'), 'good')
    expect(screen.queryByText('hello world')).not.toBeInTheDocument()
    expect(screen.getByText('goodbye')).toBeInTheDocument()
    expect(screen.getByText(/1 of 2 rows/)).toBeInTheDocument()
  })

  it('hides and restores a column', async () => {
    mockRows([row('1', { body: 'x', secret: 'hush' })])
    renderViewer()
    await screen.findByText('hush')

    await userEvent.click(screen.getByLabelText('Hide column secret'))
    expect(screen.queryByText('hush')).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /Show 1 hidden column/ }))
    expect(await screen.findByText('hush')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Row pagination and the table rail (B4-002, B4-003)
// ---------------------------------------------------------------------------

/** The viewer's own page size; a full page is what makes it ask for another. */
const ROW_PAGE_SIZE = 200
/** How many row pages the viewer holds before it evicts the oldest. */
const ROW_MAX_PAGES = 8

function pageRow(page: number, i: number): ParsedRecord {
  return {
    id: `p${page}-${i}`,
    parent_id: `a-p${page}-${i}`,
    artifact_type: 'ParsedRecord',
    metadata: {
      type: 'SqliteRow',
      // A distinct table per page keeps the rendered grid to one page of rows
      // while still exercising the paging cursor.
      table: `t${page}`,
      rowid: String(i),
      columns: { v: String(i) },
    },
  }
}

function renderSqliteViewer() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <SqliteViewer records={[]} caseId={CASE_ID} type="SqliteRow" />
    </QueryClientProvider>,
  )
}

describe('SqliteViewer row paging', () => {
  it('keeps advancing the page cursor after the row window starts evicting', async () => {
    const requested: number[] = []
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const url = new URL(request.url)
        const type = url.searchParams.get('type') ?? ''
        const page = Number(url.searchParams.get('page') ?? '1')
        const size = Number(url.searchParams.get('page_size') ?? '100')
        if (type !== 'SqliteRow') {
          return HttpResponse.json({
            records: [],
            total: 0,
            page,
            page_size: size,
            type,
          })
        }
        requested.push(page)
        return HttpResponse.json({
          records: Array.from({ length: ROW_PAGE_SIZE }, (_, i) =>
            pageRow(page, i),
          ),
          total: 100_000,
          page,
          page_size: size,
          type,
        })
      }),
    )
    renderSqliteViewer()

    const grid = await screen.findByTestId('an-db-grid-scroll')
    // One scroll pulls one page. Past ROW_MAX_PAGES the oldest page is dropped,
    // which is exactly where a cursor derived from the held page count sticks:
    // it would ask for page ROW_MAX_PAGES + 1 forever and never reach the rest
    // of the table.
    for (let page = 2; page <= ROW_MAX_PAGES + 3; page++) {
      await waitFor(
        () => {
          fireEvent.scroll(grid)
          expect(requested).toContain(page)
        },
        { timeout: 5000 },
      )
    }
    // The pages past the window are the whole point: a stuck cursor stops dead
    // at ROW_MAX_PAGES + 1 and never asks for these.
    expect(requested).toContain(ROW_MAX_PAGES + 2)
    expect(requested).toContain(ROW_MAX_PAGES + 3)
  }, 30_000)

  it('tells the examiner which slice of the table is loaded, not "the first N"', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const url = new URL(request.url)
        const type = url.searchParams.get('type') ?? ''
        const page = Number(url.searchParams.get('page') ?? '1')
        const size = Number(url.searchParams.get('page_size') ?? '100')
        const records =
          type === 'SqliteRow'
            ? Array.from({ length: ROW_PAGE_SIZE }, (_, i) => pageRow(page, i))
            : []
        return HttpResponse.json({
          records,
          total: type === 'SqliteRow' ? 100_000 : 0,
          page,
          page_size: size,
          type,
        })
      }),
    )
    renderSqliteViewer()

    const note = await screen.findByTestId('an-db-window-note')
    expect(note).toHaveTextContent('Rows 1–200 of 100,000')

    const grid = await screen.findByTestId('an-db-grid-scroll')
    await waitFor(
      () => {
        fireEvent.scroll(grid)
        expect(screen.getByTestId('an-db-window-note')).toHaveTextContent(
          'Rows 1–400 of 100,000',
        )
      },
      { timeout: 5000 },
    )
  }, 20_000)
})

describe('SqliteViewer table rail', () => {
  const summary: ParsedRecord = {
    id: 'sum-1',
    parent_id: 'db-artifact-1',
    artifact_type: 'ParsedRecord',
    metadata: {
      type: 'SqliteDatabaseForensics',
      database: 'chat.db',
      database_path: '/var/mobile/chat.db',
      database_artifact: 'db-artifact-1',
      tables: ['message', 'handle', 'attachment'],
      live_rows: 900,
      deleted_rows: 0,
      carved_rows: 0,
    },
  }

  it('lists every table in the schema, marking the ones with no rows loaded', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const url = new URL(request.url)
        const type = url.searchParams.get('type') ?? ''
        const page = Number(url.searchParams.get('page') ?? '1')
        const size = Number(url.searchParams.get('page_size') ?? '100')
        if (type === 'SqliteDatabaseForensics') {
          return HttpResponse.json({
            records: page === 1 ? [summary] : [],
            total: 1,
            page,
            page_size: size,
            type,
          })
        }
        // Only `message` rows are in the window; `handle` and `attachment` have
        // rows in the database that this page range does not cover.
        const records =
          type === 'SqliteRow' && page === 1
            ? [
                {
                  id: 'm1',
                  parent_id: 'db-artifact-1',
                  artifact_type: 'ParsedRecord',
                  metadata: {
                    type: 'SqliteRow',
                    table: 'message',
                    rowid: '1',
                    columns: { text: 'hello' },
                  },
                } as ParsedRecord,
              ]
            : []
        return HttpResponse.json({
          records,
          total: 900,
          page,
          page_size: size,
          type,
        })
      }),
    )
    renderSqliteViewer()

    // The rail is the database's schema, not the row window.
    expect(await screen.findByText('handle')).toBeInTheDocument()
    expect(screen.getByText('attachment')).toBeInTheDocument()
    expect(screen.getAllByText('no rows loaded')).toHaveLength(2)

    // Opening one of them says why the grid is empty rather than showing an
    // empty grid that reads as "this table has no rows".
    await userEvent.click(screen.getByText('handle'))
    const unloaded = await screen.findByTestId('an-db-table-unloaded')
    const said = (unloaded.textContent ?? '').replace(/\s+/g, ' ').trim()
    expect(said).toContain('No rows of handle are in the row window')
    expect(said).toContain('not a finding that the table is empty')
  })
})

describe('SqliteViewer SQL query editor', () => {
  const summary: ParsedRecord = {
    id: 'sum-1',
    parent_id: 'db-artifact-1',
    artifact_type: 'ParsedRecord',
    metadata: {
      type: 'SqliteDatabaseForensics',
      database: 'History',
      database_path: '/home/u/.config/chromium/Default/History',
      database_artifact: 'db-artifact-1',
      tables: ['urls', 'visits', 'meta'],
      live_rows: 1,
      deleted_rows: 0,
      carved_rows: 0,
    },
  }

  it('opens a read-only SQL editor for the active database and runs against its artifact', async () => {
    let posted: Record<string, unknown> | null = null
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const url = new URL(request.url)
        const type = url.searchParams.get('type') ?? ''
        const page = Number(url.searchParams.get('page') ?? '1')
        const size = Number(url.searchParams.get('page_size') ?? '100')
        const records =
          page === 1 && type === 'SqliteDatabaseForensics'
            ? [summary]
            : page === 1 && type === 'SqliteRow'
              ? [
                  {
                    id: 'u1',
                    parent_id: 'db-artifact-1',
                    artifact_type: 'ParsedRecord',
                    metadata: {
                      type: 'SqliteRow',
                      table: 'urls',
                      rowid: '1',
                      columns: { url: 'https://example.test/' },
                    },
                  } as ParsedRecord,
                ]
              : []
        return HttpResponse.json({
          records,
          total: records.length,
          page,
          page_size: size,
          type,
        })
      }),
      http.post(`/api/v1/cases/${CASE_ID}/sqlite/query`, async ({ request }) => {
        posted = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({
          columns: ['n'],
          rows: [[1]],
          row_count: 1,
          row_cap: 1000,
          capped: false,
          elapsed_ms: 1,
          timeout_ms: 10_000,
          read_only: true,
          source: 'staged_copy',
          artifact_id: 'db-artifact-1',
          database: 'History',
          content_incomplete: null,
          wal_incomplete: null,
        })
      }),
    )
    renderSqliteViewer()
    await screen.findByText('https://example.test/')

    // Closed by default: the grid is the primary surface.
    expect(screen.queryByLabelText('SQL statement')).not.toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'SQL query' }))
    const editor = screen.getByRole('region', { name: 'SQL query' })
    // Before any run the header says only what the client will ask for: the
    // database, one statement, the row ceiling. Read-only-ness and the staged
    // copy are the server's to attest, so they are absent until a result says so.
    const head = within(editor).getByTestId('sqlite-query-head')
    const headSaid = (head.textContent ?? '').replace(/\s+/g, ' ')
    expect(headSaid).toContain('History')
    expect(headSaid).toContain('one statement')
    expect(headSaid).toContain('at most 1,000 rows')
    expect(headSaid).not.toMatch(/staged copy/i)
    expect(headSaid).not.toMatch(/read-only/i)

    await userEvent.type(screen.getByLabelText('SQL statement'), 'SELECT 1 AS n')
    await userEvent.click(screen.getByRole('button', { name: 'Run' }))
    const status = await screen.findByTestId('sqlite-query-status')
    expect(posted).toMatchObject({ artifact_id: 'db-artifact-1', sql: 'SELECT 1 AS n' })
    // The attested result is where those words first appear.
    expect(status).toHaveTextContent('ran read-only over the staged copy of History')
    // And the header still does not adopt them as its own claim.
    expect((head.textContent ?? '').replace(/\s+/g, ' ')).not.toMatch(/staged copy/i)

    // The toggle closes it again.
    await userEvent.click(screen.getByRole('button', { name: 'Hide SQL query' }))
    expect(screen.queryByLabelText('SQL statement')).not.toBeInTheDocument()
  })

  it('drops a result when another database is selected, so it is never read under the wrong heading', async () => {
    const other: ParsedRecord = {
      ...summary,
      id: 'sum-2',
      parent_id: 'db-artifact-2',
      metadata: {
        ...summary.metadata,
        database: 'Cookies',
        database_artifact: 'db-artifact-2',
        tables: ['cookies', 'meta'],
        live_rows: 0,
      },
    }
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const url = new URL(request.url)
        const type = url.searchParams.get('type') ?? ''
        const page = Number(url.searchParams.get('page') ?? '1')
        const size = Number(url.searchParams.get('page_size') ?? '100')
        const records =
          page === 1 && type === 'SqliteDatabaseForensics' ? [summary, other] : []
        return HttpResponse.json({ records, total: records.length, page, page_size: size, type })
      }),
      http.post(`/api/v1/cases/${CASE_ID}/sqlite/query`, () =>
        HttpResponse.json({
          columns: ['n'],
          rows: [[1]],
          row_count: 1,
          row_cap: 1000,
          capped: false,
          elapsed_ms: 1,
          timeout_ms: 10_000,
          read_only: true,
          source: 'staged_copy',
          artifact_id: 'db-artifact-1',
          database: 'History',
          content_incomplete: null,
          wal_incomplete: null,
        }),
      ),
    )
    renderSqliteViewer()
    await screen.findByText('Cookies')

    await userEvent.click(screen.getByRole('button', { name: 'SQL query' }))
    await userEvent.type(screen.getByLabelText('SQL statement'), 'SELECT 1 AS n')
    await userEvent.click(screen.getByRole('button', { name: 'Run' }))
    await screen.findByTestId('sqlite-query-status')

    await userEvent.click(screen.getByText('Cookies'))
    const head = within(screen.getByRole('region', { name: 'SQL query' })).getByTestId(
      'sqlite-query-head',
    )
    expect(head).toHaveTextContent('Cookies')
    expect(head).not.toHaveTextContent('History')
    expect(screen.queryByTestId('sqlite-query-status')).not.toBeInTheDocument()
  })
})
