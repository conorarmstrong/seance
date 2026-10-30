import { Profiler } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import type { BookmarkCategory } from '../../api/types'
import { server } from '../../test/server'
import { BookmarkControl } from './BookmarkControl'
import { BookmarksProvider } from './BookmarksProvider'

const CASE = 'case-1'
const CATEGORIES: BookmarkCategory[] = [
  {
    id: 'cat-1',
    case_id: CASE,
    name: 'Key Evidence',
    color: '#e05c5c',
    created_at: 1700000000,
  },
]

function mockApi(ids: string[] = []) {
  const created: Record<string, unknown>[] = []
  server.use(
    http.get(`/api/v1/cases/${CASE}/bookmarks/ids`, () =>
      HttpResponse.json(ids),
    ),
    http.get(`/api/v1/cases/${CASE}/bookmarks/categories`, () =>
      HttpResponse.json(CATEGORIES),
    ),
    http.get(`/api/v1/cases/${CASE}/bookmarks/:artifactId`, () =>
      HttpResponse.json({
        id: 'bm-1',
        case_id: CASE,
        artifact_id: 'art-1',
        category_id: 'cat-1',
        category_name: 'Key Evidence',
        category_color: '#e05c5c',
        note: 'the stored note',
        examiner: 'alice',
        created_at: 1767225600,
        updated_at: 1767225600,
      }),
    ),
    http.post(`/api/v1/cases/${CASE}/bookmarks`, async ({ request }) => {
      created.push((await request.json()) as Record<string, unknown>)
      return HttpResponse.json({ id: 'bm-new' })
    }),
  )
  return created
}

function renderControl(artifactId = 'art-1') {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <BookmarkControl
        caseId={CASE}
        artifactId={artifactId}
        subject="the 03:12 message to +44 7700 900123"
      />
    </QueryClientProvider>,
  )
}

describe('BookmarkControl', () => {
  it('records the note and the category at the moment of discovery', async () => {
    const created = mockApi()
    const user = userEvent.setup()
    renderControl()

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /bookmark/i })).toBeEnabled(),
    )
    await user.click(screen.getByRole('button', { name: /bookmark/i }))

    await user.type(
      screen.getByLabelText(/why this matters/i),
      'matches CCTV entry time',
    )
    await user.selectOptions(screen.getByLabelText(/category/i), 'cat-1')
    await user.click(screen.getByRole('button', { name: /^save bookmark$/i }))

    await waitFor(() =>
      expect(created).toEqual([
        {
          artifact_id: 'art-1',
          category_id: 'cat-1',
          note: 'matches CCTV entry time',
        },
      ]),
    )
  })

  it('keeps the one-keystroke path: open, Enter, bookmarked with no note', async () => {
    const created = mockApi()
    const user = userEvent.setup()
    renderControl()

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /bookmark/i })).toBeEnabled(),
    )
    await user.click(screen.getByRole('button', { name: /bookmark/i }))
    // The note box takes focus on open, so Enter here is the fast capture.
    await user.keyboard('{Enter}')

    await waitFor(() =>
      expect(created).toEqual([{ artifact_id: 'art-1' }]),
    )
  })

  it('writes nothing when the popover is dismissed', async () => {
    const created = mockApi()
    const user = userEvent.setup()
    renderControl()

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /bookmark/i })).toBeEnabled(),
    )
    await user.click(screen.getByRole('button', { name: /bookmark/i }))
    await user.type(screen.getByLabelText(/why this matters/i), 'half a thought')
    await user.keyboard('{Escape}')

    await waitFor(() =>
      expect(screen.queryByLabelText(/why this matters/i)).toBeNull(),
    )
    // Escape means "I did not mean to record this". Saving on dismissal would
    // put half-written reasoning into the report.
    expect(created).toEqual([])
  })

  it('says the marked state is unknown rather than showing it as unmarked', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE}/bookmarks/ids`, () =>
        HttpResponse.json({ error: 'boom' }, { status: 500 }),
      ),
      http.get(`/api/v1/cases/${CASE}/bookmarks/categories`, () =>
        HttpResponse.json(CATEGORIES),
      ),
    )
    renderControl()
    const button = await screen.findByRole('button', {
      name: /bookmark state unknown/i,
    })
    expect(button).toHaveAttribute('aria-pressed', 'false')
    expect(button).toBeDisabled()
  })

  it('keeps a failed capture on screen and says it was not recorded', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE}/bookmarks/ids`, () => HttpResponse.json([])),
      http.get(`/api/v1/cases/${CASE}/bookmarks/categories`, () =>
        HttpResponse.json(CATEGORIES),
      ),
      http.post(`/api/v1/cases/${CASE}/bookmarks`, () =>
        HttpResponse.json({ error: 'boom' }, { status: 500 }),
      ),
    )
    const user = userEvent.setup()
    renderControl()

    await waitFor(() =>
      expect(screen.getByRole('button', { name: /bookmark/i })).toBeEnabled(),
    )
    await user.click(screen.getByRole('button', { name: /bookmark/i }))
    await user.type(screen.getByLabelText(/why this matters/i), 'the reason')
    await user.click(screen.getByRole('button', { name: /^save bookmark$/i }))

    // The form stays open with the note still in it, and says plainly that
    // nothing was written. Closing over the failure would leave the examiner
    // believing their reasoning is on the record.
    expect(await screen.findByRole('alert')).toHaveTextContent(/NOT saved/)
    expect(screen.getByLabelText(/why this matters/i)).toHaveValue('the reason')
  })

  it('loads the stored note before letting an existing bookmark be edited', async () => {
    mockApi(['art-1'])
    const user = userEvent.setup()
    renderControl()

    const button = await screen.findByRole('button', {
      name: /edit bookmark/i,
    })
    await user.click(button)

    // Until the stored note is in hand the Save button is held, because saving
    // a form that has not yet been filled from the record would blank a note
    // the control never showed anyone.
    expect(
      await screen.findByDisplayValue('the stored note'),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^save bookmark$/i })).toBeEnabled()
  })
})

describe('BookmarkControl keyboard focus', () => {
  it('returns focus to the control the form was opened from', async () => {
    mockApi()
    const user = userEvent.setup()
    renderControl()

    const star = await screen.findByRole('button', { name: /^Bookmark the/ })
    await user.click(star)
    expect(screen.getByLabelText(/why this matters/i)).toHaveFocus()

    await user.keyboard('{Escape}')
    // Focus has to come back, or the next Tab restarts at the top of the
    // document and a keyboard examiner loses their place in the table.
    await waitFor(() => expect(star).toHaveFocus())
  })
})

/**
 * What a table of these costs when one of them changes.
 *
 * The comms table renders one control per row up to a cap of five hundred, so
 * the question is not what one control costs but what one CAPTURE costs across
 * all of them. Under a shared provider the case's list is fetched once; this
 * pins the other half — that the answer is delivered per row, so the other
 * four hundred and ninety-nine rows are not repainted because one row was
 * bookmarked.
 */
describe('BookmarkControl at table scale', () => {
  const IDS = Array.from({ length: 20 }, (_, i) => `art-${i}`)

  it('repaints only the row whose bookmark state changed', async () => {
    mockApi()
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const renders = new Map<string, number>()

    render(
      <QueryClientProvider client={client}>
        <BookmarksProvider caseId={CASE}>
          {IDS.map((id) => (
            <Profiler
              key={id}
              id={id}
              onRender={() => renders.set(id, (renders.get(id) ?? 0) + 1)}
            >
              <BookmarkControl caseId={CASE} artifactId={id} subject={id} />
            </Profiler>
          ))}
        </BookmarksProvider>
      </QueryClientProvider>,
    )

    await waitFor(() =>
      expect(screen.getAllByRole('button', { name: /^Bookmark art-0$/ })[0])
        .toBeEnabled(),
    )
    renders.clear()

    // A capture landing anywhere in the case arrives as a new id list, which is
    // exactly what an invalidation after a write produces.
    act(() => {
      client.setQueryData(['bookmarks', CASE, 'ids'], ['art-7'])
    })

    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: /^Edit bookmark for art-7$/ }),
      ).toBeInTheDocument(),
    )
    expect([...renders.keys()].filter((id) => id !== 'art-7')).toEqual([])
  })

  it('still gives each row the state that belongs to it', async () => {
    mockApi(['art-3'])
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <BookmarksProvider caseId={CASE}>
          {IDS.map((id) => (
            <BookmarkControl key={id} caseId={CASE} artifactId={id} subject={id} />
          ))}
        </BookmarksProvider>
      </QueryClientProvider>,
    )

    // Sharing the lookup must not share the answer: one row is marked and the
    // rest are not, and every one of them says which it is rather than showing
    // an unknown state as an unmarked one.
    expect(
      await screen.findByRole('button', { name: /^Edit bookmark for art-3$/ }),
    ).toBeInTheDocument()
    expect(
      screen.getAllByRole('button', { name: /^Bookmark art-/ }),
    ).toHaveLength(IDS.length - 1)
  })
})
