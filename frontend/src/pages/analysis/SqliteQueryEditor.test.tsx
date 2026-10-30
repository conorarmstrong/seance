import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { beforeEach, describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import type { SqliteQueryResponse } from './SqliteQueryApi'
import { SQLITE_QUERY_ROW_CAP } from './SqliteQueryApi'
import { SqliteQueryEditor, type SqliteQueryTarget } from './SqliteQueryEditor'
import { historyKey, loadHistory, SQLITE_HISTORY_MAX } from './SqliteQueryHistory'

const CASE_ID = 'case-1'
const ROUTE = `/api/v1/cases/${CASE_ID}/sqlite/query`

const HISTORY_DB = {
  name: 'History',
  artifactId: 'db-artifact-1',
  tableNames: ['urls', 'visits', 'meta'],
}

function answer(over: Partial<SqliteQueryResponse> = {}): SqliteQueryResponse {
  return {
    columns: ['url', 'title'],
    rows: [
      ['https://example.test/', 'Example'],
      ['https://other.test/', null],
    ],
    row_count: 2,
    row_cap: SQLITE_QUERY_ROW_CAP,
    capped: false,
    elapsed_ms: 3,
    timeout_ms: 10_000,
    read_only: true,
    source: 'staged_copy',
    artifact_id: 'db-artifact-1',
    database: 'History',
    content_incomplete: null,
    wal_incomplete: null,
    ...over,
  }
}

interface Seen {
  body: Record<string, unknown> | null
}

function mockQuery(
  respond: SqliteQueryResponse | { status: number; code: string; message: string },
): Seen {
  const seen: Seen = { body: null }
  server.use(
    http.post(ROUTE, async ({ request }) => {
      seen.body = (await request.json()) as Record<string, unknown>
      if ('status' in respond) {
        return HttpResponse.json(
          { error: { code: respond.code, message: respond.message } },
          { status: respond.status },
        )
      }
      return HttpResponse.json(respond)
    }),
  )
  return seen
}

function renderEditor(database: SqliteQueryTarget | null = HISTORY_DB) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <SqliteQueryEditor caseId={CASE_ID} database={database} />
    </QueryClientProvider>,
  )
}

async function typeAndRun(sql: string) {
  const box = screen.getByLabelText('SQL statement')
  await userEvent.clear(box)
  await userEvent.type(box, sql)
  await userEvent.click(screen.getByRole('button', { name: 'Run' }))
}

describe('SqliteQueryEditor', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('runs one statement over the staged copy and reports the row cap that applied', async () => {
    const seen = mockQuery(answer())
    renderEditor()

    await typeAndRun('SELECT url, title FROM urls')

    expect(await screen.findByText('https://example.test/')).toBeInTheDocument()
    expect(screen.getByText('Example')).toBeInTheDocument()
    expect(screen.getByText('NULL')).toBeInTheDocument()
    expect(seen.body).toMatchObject({
      artifact_id: 'db-artifact-1',
      sql: 'SELECT url, title FROM urls',
      max_rows: SQLITE_QUERY_ROW_CAP,
    })

    const status = screen.getByTestId('sqlite-query-status')
    const said = (status.textContent ?? '').replace(/\s+/g, ' ')
    expect(said).toContain('2 rows')
    expect(said).toContain('cap of 1,000 rows was not reached')
    expect(said).toContain('read-only')
    expect(said).toContain('staged copy')
    expect(said).toContain('not the evidence file')
  })

  it('says when the row cap was hit, with the number', async () => {
    mockQuery(
      answer({
        rows: Array.from({ length: 1000 }, (_, i) => [`u${i}`, null]),
        row_count: 1000,
        row_cap: 1000,
        capped: true,
      }),
    )
    renderEditor()
    await typeAndRun('SELECT url, title FROM urls')

    const status = await screen.findByTestId('sqlite-query-status')
    const said = (status.textContent ?? '').replace(/\s+/g, ' ')
    expect(said).toContain('cap of 1,000 rows was hit')
    expect(said).toContain('more rows exist')
    expect(status.querySelector('.badge-warn')).not.toBeNull()
  })

  it("shows the server's refusal instead of a result, and keeps it in the history", async () => {
    mockQuery({
      status: 400,
      code: 'sql_not_readonly',
      message: 'only a single SELECT statement is accepted',
    })
    renderEditor()
    await typeAndRun('DELETE FROM urls')

    const err = await screen.findByRole('alert')
    expect(err).toHaveTextContent('sql_not_readonly')
    expect(err).toHaveTextContent('only a single SELECT statement is accepted')
    expect(screen.queryByTestId('sqlite-query-status')).not.toBeInTheDocument()

    const [entry] = loadHistory(CASE_ID)
    expect(entry.sql).toBe('DELETE FROM urls')
    expect(entry.outcome).toBe('error')
  })

  it('inserts a template, and disables the ones whose tables this database lacks, naming them', async () => {
    renderEditor()
    const picker = screen.getByLabelText('Query template')

    const chrome = within(picker).getByRole('option', {
      name: /Chrome \/ Chromium History: URLs by last visit/,
    })
    expect(chrome).not.toBeDisabled()

    const firefox = within(picker).getByRole('option', {
      name: /Firefox places: history visits/,
    })
    expect(firefox).toBeDisabled()
    expect(firefox.textContent).toContain('missing moz_historyvisits, moz_places')

    await userEvent.selectOptions(picker, chrome)
    const box = screen.getByLabelText('SQL statement') as HTMLTextAreaElement
    expect(box.value).toContain('FROM urls')
    expect(box.value).toContain('last_visit_utc')
    expect(screen.getByTestId('sqlite-template-notes')).toHaveTextContent(
      'reference/plaso/test_data/chrome_history/History',
    )
  })

  it('offers every template, and says applicability was not checked, when the schema was never listed', () => {
    renderEditor({ ...HISTORY_DB, tableNames: [] })
    const picker = screen.getByLabelText('Query template')
    const firefox = within(picker).getByRole('option', {
      name: /Firefox places: history visits/,
    })
    expect(firefox).not.toBeDisabled()
    expect(screen.getByTestId('sqlite-template-unchecked')).toHaveTextContent(
      'no table list',
    )
  })

  it("records runs in this browser's history under the case, and reloads one into the editor", async () => {
    mockQuery(answer())
    renderEditor()
    await typeAndRun('SELECT url, title FROM urls')
    await screen.findByTestId('sqlite-query-status')

    const raw = localStorage.getItem(historyKey(CASE_ID))
    expect(raw).not.toBeNull()
    const [entry] = loadHistory(CASE_ID)
    expect(entry).toMatchObject({
      sql: 'SELECT url, title FROM urls',
      artifactId: 'db-artifact-1',
      database: 'History',
      outcome: 'ok',
      rowCount: 2,
      capped: false,
    })

    const history = screen.getByRole('list', { name: 'Query history' })
    expect(history).toHaveTextContent('SELECT url, title FROM urls')
    expect(history).toHaveTextContent('2 rows')

    await userEvent.clear(screen.getByLabelText('SQL statement'))
    await userEvent.click(
      within(history).getByRole('button', { name: /SELECT url, title FROM urls/ }),
    )
    expect((screen.getByLabelText('SQL statement') as HTMLTextAreaElement).value).toBe(
      'SELECT url, title FROM urls',
    )

    expect(screen.getByTestId('sqlite-history-scope')).toHaveTextContent(
      `this browser only`,
    )
    expect(screen.getByTestId('sqlite-history-scope')).toHaveTextContent(
      `${SQLITE_HISTORY_MAX}`,
    )
  })

  it('cannot run without a staged copy to run over', () => {
    renderEditor({ name: 'legacy.db', artifactId: null, tableNames: [] })
    expect(screen.getByRole('button', { name: 'Run' })).toBeDisabled()
    expect(screen.getByTestId('sqlite-query-no-artifact')).toHaveTextContent(
      'no artifact id',
    )
  })

  it('does not claim a read-only staged run the server did not attest', async () => {
    mockQuery(answer({ read_only: false, source: 'unknown' }))
    renderEditor()

    // Before any run the header may state only what the client asks for;
    // "staged copy" and "read-only" are the server's words to earn.
    const headBefore = (screen.getByTestId('sqlite-query-head').textContent ?? '').replace(
      /\s+/g,
      ' ',
    )
    expect(headBefore).toContain('at most 1,000 rows')
    expect(headBefore).not.toMatch(/staged copy|read-only/i)

    await typeAndRun('SELECT 1')

    const status = await screen.findByTestId('sqlite-query-status')
    const said = (status.textContent ?? '').replace(/\s+/g, ' ')
    expect(said).not.toContain('ran read-only over the staged copy')
    expect(said).toContain('did not attest')
    // A non-attested result does not put those words into the header either.
    const headAfter = (screen.getByTestId('sqlite-query-head').textContent ?? '').replace(
      /\s+/g,
      ' ',
    )
    expect(headAfter).not.toMatch(/staged copy|read-only/i)
  })

  it("carries the staged copy's incompleteness onto the result", async () => {
    mockQuery(answer({ content_incomplete: 'cap_reached', wal_incomplete: 'wal_not_reachable' }))
    renderEditor()
    await typeAndRun('SELECT 1')

    const note = await screen.findByTestId('sqlite-query-incomplete')
    expect(note).toHaveTextContent('cap_reached')
    expect(note).toHaveTextContent('wal_not_reachable')
    expect(note).toHaveTextContent('not the whole database')
  })

  it('reinterprets a result column as a timestamp in place', async () => {
    mockQuery(
      answer({
        columns: ['ts'],
        rows: [[1700000000]],
        row_count: 1,
      }),
    )
    renderEditor()
    await typeAndRun('SELECT ts FROM t')
    expect(await screen.findByText('1700000000')).toBeInTheDocument()

    await userEvent.selectOptions(screen.getByLabelText('Interpret ts as'), 'Unix (seconds)')
    expect(await screen.findByText('2023-11-14T22:13:20Z')).toBeInTheDocument()
  })

  it('reports a blob by its size rather than inlining it', async () => {
    mockQuery(
      answer({
        columns: ['data'],
        rows: [[{ blob: true, size: 4096 }]],
        row_count: 1,
      }),
    )
    renderEditor()
    await typeAndRun('SELECT data FROM t')
    expect(await screen.findByText('[blob 4,096 bytes]')).toBeInTheDocument()
  })

  it('runs on Ctrl+Enter from the editor', async () => {
    const seen = mockQuery(answer())
    renderEditor()
    const box = screen.getByLabelText('SQL statement')
    await userEvent.type(box, 'SELECT 1')
    await userEvent.keyboard('{Control>}{Enter}{/Control}')
    await waitFor(() => expect(seen.body).not.toBeNull())
    expect(seen.body).toMatchObject({ sql: 'SELECT 1' })
  })
})
