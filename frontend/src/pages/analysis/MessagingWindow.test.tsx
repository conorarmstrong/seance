import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { ToastProvider } from '../../components/toast/ToastProvider'
import { PivotCtx } from '../../app/PivotContext'
import { IMessageViewer } from './MessagingViewer'

const CASE_ID = 'c1'
const THREAD = '+15550000000'
/** Must equal the viewer's page size, or `getNextPageParam` stops the walk. */
const PAGE = 60

/**
 * The server's cursor contract, enforced.
 *
 * `before` and `before_id` must arrive together — resuming from an ordering
 * value alone would drop every message sharing it, so the real handler answers
 * a half-cursor with a 400. These mocks used to accept `before` on its own and
 * serve a full page, which is the pre-fix contract and no build has ever
 * spoken it. The whole suite passed while every scrollback page 400'd in the
 * product.
 *
 * Returns an error response when the cursor is malformed, or null when it is
 * acceptable.
 */
function cursorRefusal(request: Request): Response | null {
  const url = new URL(request.url)
  const before = url.searchParams.get('before')
  const beforeId = url.searchParams.get('before_id')
  if ((before == null) !== (beforeId == null)) {
    return HttpResponse.json(
      {
        error:
          "'before' and 'before_id' must be sent together: resuming from an " +
          'ordering value alone would drop every message sharing it.',
      },
      { status: 400 },
    )
  }
  return null
}

/**
 * A conversation long enough that scrolling back evicts the newest pages.
 *
 * The endpoint is a cursor pager: the cursor is `{before, before_id}` and a
 * full page always implies another page behind it. Serving a full page for
 * every cursor gives an effectively endless thread, which is the condition the
 * sliding window exists for.
 */
function mockEndlessThread() {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/conversations`, () =>
      HttpResponse.json({
        conversations: [
          {
            key: THREAD,
            label: 'Alex',
            count: 100000,
            last_time: 1_700_000_000,
            last_preview: 'ok',
            is_group: false,
            tag: null,
          },
        ],
      }),
    ),
    http.get(`/api/v1/cases/${CASE_ID}/conversations/messages`, ({ request }) => {
      const refused = cursorRefusal(request)
      if (refused) return refused
      const before = new URL(request.url).searchParams.get('before')
      const newest = before ? Number(before) - 1 : 1_700_000_000
      const oldest = newest - (PAGE - 1)
      return HttpResponse.json({
        records: Array.from({ length: PAGE }, (_, i) => ({
          id: `m-${newest - i}`,
          parent_id: 'db1',
          artifact_type: 'ParsedRecord',
          metadata: {
            type: 'iMessage',
            guid: `g-${newest - i}`,
            date: newest - i,
            text: `message ${newest - i}`,
            is_from_me: false,
            chat_identifier: THREAD,
          },
        })),
        attachments: [],
        // The server hands back where to resume; the client no longer computes
        // it from the last record's timestamp.
        has_more: true,
        undecodable: 0,
        next_cursor: { before: oldest, before_id: `m-${oldest}` },
      })
    }),
    // The contact index pages /records; an empty address book is enough.
    http.get(`/api/v1/cases/${CASE_ID}/records`, () =>
      HttpResponse.json({
        records: [],
        total: 0,
        page: 1,
        page_size: 500,
        type: 'Contact',
      }),
    ),
  )
}

/** One iMessage row in the shape `/conversations/messages` returns. */
function message(
  id: string,
  date: number,
  text: string,
  /** Extra metadata for the cases that need one more key (a sender handle,
   *  an outgoing flag) without a second fixture. */
  extra: Record<string, unknown> = {},
) {
  return {
    id,
    parent_id: 'db1',
    artifact_type: 'ParsedRecord',
    metadata: {
      type: 'iMessage',
      guid: `g-${id}`,
      date,
      text,
      is_from_me: false,
      chat_identifier: THREAD,
      ...extra,
    },
  }
}

/**
 * A thread served with the server's real cursor semantics: `ord < before`,
 * ordered by date descending, capped at one page.
 *
 * This is the shape that loses messages. The filter is exclusive on a single
 * timestamp, so a page that ends inside a burst of messages sharing one second
 * used to leave the rest of that burst permanently unreachable (B8-001).
 */
function mockThread(all: ReturnType<typeof message>[]) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/conversations`, () =>
      HttpResponse.json({
        conversations: [
          {
            key: THREAD,
            label: 'Alex',
            count: all.length,
            last_time: all[0]?.metadata.date ?? 0,
            last_preview: 'ok',
            is_group: false,
            tag: null,
          },
        ],
      }),
    ),
    http.get(`/api/v1/cases/${CASE_ID}/conversations/messages`, ({ request }) => {
      const refused = cursorRefusal(request)
      if (refused) return refused
      const params = new URL(request.url).searchParams
      const raw = params.get('before')
      const before = raw == null ? null : Number(raw)
      const beforeId = params.get('before_id')
      // The server's real predicate:
      //   ord < ?  OR  (ord = ? AND id < ?)
      // The id half is the whole point — without it a page ending inside a
      // burst of messages sharing one date loses the rest of that burst.
      const ordered = all
        .filter((m) => {
          if (before == null || beforeId == null) return true
          if (m.metadata.date < before) return true
          return m.metadata.date === before && m.id < beforeId
        })
        .sort(
          (a, b) =>
            b.metadata.date - a.metadata.date || b.id.localeCompare(a.id),
        )
      const rows = ordered.slice(0, PAGE)
      const last = rows[rows.length - 1]
      return HttpResponse.json({
        records: rows,
        attachments: [],
        has_more: ordered.length > PAGE,
        undecodable: 0,
        next_cursor: last
          ? { before: last.metadata.date, before_id: last.id }
          : null,
      })
    }),
    http.get(`/api/v1/cases/${CASE_ID}/records`, () =>
      HttpResponse.json({
        records: [],
        total: 0,
        page: 1,
        page_size: 500,
        type: 'Contact',
      }),
    ),
  )
}

function renderViewer() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter>
          <IMessageViewer caseId={CASE_ID} type="iMessage" records={[]} />
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

describe('MessagingViewer scrollback cursor (B8-001)', () => {
  it('does not lose the messages that share the second a page ends on', async () => {
    // 59 dated messages, then a burst of five sent inside one second. The first
    // page holds all 59 plus one of the burst, so the cursor lands ON that
    // second — and an exclusive `ord < cursor` skips the other four. They are
    // in the database, they are in the thread, and the pane showed no sign that
    // anything was missing.
    const all = [
      ...Array.from({ length: 59 }, (_, i) =>
        message(`m-${2000 + i}`, 2000 + i, `message ${2000 + i}`),
      ),
      ...Array.from({ length: 5 }, (_, i) =>
        message(`burst-${i}`, 1000, `burst ${i}`),
      ),
    ]
    mockThread(all)
    renderViewer()

    await screen.findByText('message 2058')
    await userEvent.click(
      await screen.findByRole('button', { name: /Load older messages/ }),
    )

    for (let i = 0; i < 5; i += 1) {
      expect(await screen.findByText(`burst ${i}`)).toBeInTheDocument()
    }
    // The overlap the cursor deliberately re-requests must not double anything.
    expect(screen.getAllByText('burst 0')).toHaveLength(1)
  }, 20_000)

  it('walks past a burst bigger than a page (B8-001)', async () => {
    // 65 messages sharing one timestamp, against a page of 60.
    //
    // A timestamp-only cursor could not get past this: the next request would
    // ask for the same second again, so the pane stopped and said it could not
    // continue. The five oldest messages were unreachable in the product and
    // this test asserted that as correct behaviour.
    //
    // The cursor carries the tie-breaking id now, so page two resumes at
    // `(1000, same-05)` and returns exactly the remainder. Nothing is stranded,
    // and nothing is served twice.
    const all = Array.from({ length: 65 }, (_, i) =>
      message(`same-${String(i).padStart(2, '0')}`, 1000, `same ${i}`),
    )
    mockThread(all)
    renderViewer()

    await screen.findByText('same 64')
    await userEvent.click(
      await screen.findByRole('button', { name: /Load older messages/ }),
    )

    // The five that the old cursor could never reach.
    for (const i of [4, 3, 2, 1, 0]) {
      expect(await screen.findByText(`same ${i}`)).toBeInTheDocument()
    }
    // Every message exactly once: the tuple cursor does not re-serve the
    // boundary the way the overlapping timestamp cursor had to.
    expect(screen.getAllByText('same 64')).toHaveLength(1)
    expect(screen.getAllByText('same 0')).toHaveLength(1)
  }, 20_000)
})

describe('MessagingViewer scrollback window', () => {
  it('says nothing about a window while the newest messages are still held', async () => {
    mockEndlessThread()
    renderViewer()
    expect(await screen.findByText('message 1700000000')).toBeInTheDocument()
    expect(screen.queryByText(/not the end of the thread/i)).toBeNull()
  })

  it('warns once scrolling back has evicted the newest messages (B3-057)', async () => {
    mockEndlessThread()
    renderViewer()
    await screen.findByText('message 1700000000')

    // Eight pages fit; the ninth request drops the newest one. From that point
    // the last message in the pane is NOT the last message of the conversation,
    // and a screenshot or report of it would present a middle window as the end
    // of the thread.
    for (let i = 0; i < 8; i += 1) {
      await userEvent.click(
        await screen.findByRole('button', { name: /Load older messages/ }),
      )
    }

    expect(
      await screen.findByText(/not the end of the thread/i),
    ).toBeInTheDocument()
    // The newest message really is gone: the banner is describing what happened.
    expect(screen.queryByText('message 1700000000')).toBeNull()

    // And there is a way back to the newest messages, not just a warning.
    await userEvent.click(
      screen.getByRole('button', { name: /Back to the newest messages/ }),
    )
    await waitFor(() =>
      expect(screen.getByText('message 1700000000')).toBeInTheDocument(),
    )
    expect(screen.queryByText(/not the end of the thread/i)).toBeNull()
    // Nine sequential paginated fetches — the eight that fill the window plus
    // the one that evicts — so this runs close to the 5s default on its own and
    // over it whenever the worker pool is busy. The page count is what the
    // behaviour under test is about and cannot be reduced, so the budget is
    // raised instead of the coverage being cut.
  }, 30_000)
})

/**
 * §5.1. A participant's name on a message is a pivot trigger on the handle the
 * chat database stored, so "what else in this case touches this person" is one
 * click from the thread. A message of mine has no counterparty, so it offers
 * no trigger — a dead affordance is worse than none.
 */
describe('MessagingViewer participant pivots', () => {
  function renderWithPivot(records: ReturnType<typeof message>[]) {
    const pivoted: string[] = []
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    mockThread(records)
    render(
      <PivotCtx.Provider value={{ openPivot: (v) => pivoted.push(v) }}>
        <QueryClientProvider client={client}>
          <ToastProvider>
            <MemoryRouter>
              <IMessageViewer caseId={CASE_ID} type="iMessage" records={[]} />
            </MemoryRouter>
          </ToastProvider>
        </QueryClientProvider>
      </PivotCtx.Provider>,
    )
    return pivoted
  }

  it('pivots on the sender handle of a received message', async () => {
    const pivoted = renderWithPivot([
      message('in-1', 3000, 'from them', { contact: 'alice@example.com' }),
    ])

    await screen.findByText('from them')
    await userEvent.click(
      screen.getByRole('button', { name: 'alice@example.com' }),
    )
    expect(pivoted).toEqual(['alice@example.com'])
  })

  it('offers no trigger on my own message', async () => {
    renderWithPivot([
      message('out-1', 3000, 'from me', { is_from_me: true }),
    ])

    await screen.findByText('from me')
    // "Me" is shown so the bubble still says who sent it, but it is not a
    // trigger: there is no counterparty identifier to pivot on.
    expect(screen.getByText('Me')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Me' })).toBeNull()
  })
})
