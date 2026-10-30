import { Profiler } from 'react'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { beforeEach, describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { resetReviewLedger } from '../../hooks/useReviewed'
import { ReviewLedgerPanel, ReviewMark } from './ReviewMark'

const CASE = 'case-1'

/** What the case's ledger holds, as the two endpoints the panel reads report it. */
interface LedgerState {
  /** Artifacts anybody has opened. */
  opened?: string[]
  /** Artifacts anybody currently has reviewed. */
  reviewed?: string[]
  /** Artifacts THIS examiner has reviewed. */
  mine?: string[]
  /** Report the id listings as having stopped at their ceiling. */
  capped?: boolean
  examiners?: {
    examiner: string
    opened: number
    reviewed: number
    first_opened_at: number
    last_activity_at: number
  }[]
  population?: number
}

function mockLedger(state: LedgerState) {
  server.use(
    http.get('/api/v1/cases/:caseId/artifact_reviews/ids', ({ request }) => {
      const url = new URL(request.url)
      const which = url.searchParams.get('state') ?? 'reviewed'
      const examiner = url.searchParams.get('examiner')
      const ids =
        which === 'opened'
          ? (state.opened ?? [])
          : examiner
            ? (state.mine ?? [])
            : (state.reviewed ?? [])
      return HttpResponse.json({
        ids,
        state: which,
        examiner,
        scope: examiner ? 'examiner' : 'case',
        total: state.capped ? ids.length + 7 : ids.length,
        returned: ids.length,
        capped: state.capped === true,
        cap: 100_000,
      })
    }),
    http.get('/api/v1/cases/:caseId/artifact_reviews/stats', () =>
      HttpResponse.json({
        examiners: state.examiners ?? [],
        case: {
          opened: (state.opened ?? []).length,
          reviewed: (state.reviewed ?? []).length,
        },
        population: {
          total: state.population ?? 4_012_345,
          name: 'artifacts_in_case',
          label: 'every artifact recorded in this case, of every type',
          includes_non_reviewable_rows: true,
          exact: true,
        },
        reviewed_is_subset_of_opened: true,
        counts_are_distinct_artifacts: true,
      }),
    ),
    http.post('/api/v1/cases/:caseId/artifact_reviews', async ({ request }) => {
      const body = (await request.json()) as {
        marks: { artifact_id: string; state: string }[]
      }
      return HttpResponse.json({
        examiner: 'alice',
        received: body.marks.length,
        openings_recorded: body.marks.length,
        reviews_recorded: body.marks.filter((m) => m.state === 'reviewed')
          .length,
        reviews_withdrawn: body.marks.filter((m) => m.state === 'unreviewed')
          .length,
        unchanged: 0,
        rejected: [],
        rejected_reason: 'artifact_not_in_case',
        batch_max: 1000,
      })
    }),
    http.get('/api/v1/cases/:caseId/artifact_reviews/history', () =>
      HttpResponse.json({
        events: [],
        artifact_id: null,
        examiner: null,
        returned: 0,
        limit: 1000,
        capped: false,
      }),
    ),
  )
}

beforeEach(() => {
  localStorage.clear()
  localStorage.setItem(
    'seance_session',
    JSON.stringify({ username: 'alice', role: 'examiner' }),
  )
  resetReviewLedger()
})

describe('ReviewMark', () => {
  it('records a review and offers it back as yours to withdraw', async () => {
    mockLedger({})
    const user = userEvent.setup()
    render(<ReviewMark caseId={CASE} id="art-1" subject="row 1" />)

    const toggle = await screen.findByRole('button', {
      name: /^Mark row 1 reviewed$/,
    })
    expect(toggle).toHaveAttribute('aria-pressed', 'false')
    await user.click(toggle)

    const cleared = await screen.findByRole('button', {
      name: /reviewed by you — withdraw the review of row 1/i,
    })
    expect(cleared).toHaveAttribute('aria-pressed', 'true')
    // The mark is on the case, not on this machine, and the control says so
    // where an examiner about to press it will read it.
    expect(cleared.getAttribute('title')).toMatch(/every examiner/i)
    expect(cleared.getAttribute('title')).not.toMatch(/this browser/i)
  })

  it('names a colleague’s review rather than offering to withdraw it', async () => {
    // Reviewed on the case, but not by this examiner: the server files a
    // withdrawal against the examiner who made the review, so a withdraw
    // control here would appear to do nothing.
    mockLedger({ opened: ['art-1'], reviewed: ['art-1'], mine: [] })
    render(<ReviewMark caseId={CASE} id="art-1" subject="row 1" />)

    expect(
      await screen.findByText(/reviewed by another examiner/i),
    ).toBeInTheDocument()
    const toggle = screen.getByRole('button', {
      name: /Mark row 1 reviewed \(another examiner has already reviewed it\)/i,
    })
    expect(toggle).toHaveAttribute('aria-pressed', 'false')
  })

  it('shows an opened row as opened and not as reviewed', async () => {
    mockLedger({ opened: ['art-1'] })
    render(<ReviewMark caseId={CASE} id="art-1" subject="row 1" />)

    expect(await screen.findByText(/^opened$/i)).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /^Mark row 1 reviewed$/ }),
    ).toHaveAttribute('aria-pressed', 'false')
  })

  it('says a row is not known rather than drawing it as unreviewed', async () => {
    // Nothing has answered yet, and past the listing's ceiling nothing ever
    // will. Painting the row as never-opened would be a false absence about
    // the whole case, made out of a fact about one request.
    mockLedger({ capped: true })
    render(<ReviewMark caseId={CASE} id="art-1" subject="row 1" />)

    expect(await screen.findByText(/not known/i)).toBeInTheDocument()
    const toggle = screen.getByRole('button', {
      name: /its review state has not been read/i,
    })
    expect(toggle).toHaveAttribute('aria-pressed', 'mixed')
  })

  it('says a mark was refused instead of showing it anyway', async () => {
    mockLedger({})
    server.use(
      http.post('/api/v1/cases/:caseId/artifact_reviews', () =>
        HttpResponse.json(
          {
            error: {
              code: 'JOB_FAILED',
              message: 'An internal error occurred (reference DEADBEEF).',
            },
          },
          { status: 500 },
        ),
      ),
    )
    const user = userEvent.setup()
    render(<ReviewMark caseId={CASE} id="art-1" subject="row 1" />)

    await user.click(
      await screen.findByRole('button', { name: /^Mark row 1 reviewed$/ }),
    )

    // Said out loud on the row, not swallowed: an examiner who believes they
    // marked a record reviewed will not come back to it.
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/not recorded/i)
    expect(
      screen.getByRole('button', { name: /^Mark row 1 reviewed$/ }),
    ).toHaveAttribute('aria-pressed', 'false')
  })
})

describe('ReviewLedgerPanel', () => {
  it('states counts against a named population and never as a percentage', async () => {
    mockLedger({ opened: ['a', 'b', 'c'], reviewed: ['a'] })
    render(
      <ReviewLedgerPanel
        caseId={CASE}
        population={{ count: 4_000_000, noun: 'artifacts in this case' }}
      />,
    )

    const panel = screen.getByRole('region', { name: /review ledger/i })
    await waitFor(() =>
      expect(within(panel).getByText(/1 of 4,000,000/)).toBeInTheDocument(),
    )
    expect(
      within(panel).getByText(/artifacts in this case/),
    ).toBeInTheDocument()
    expect(panel.textContent).not.toMatch(/%/)
  })

  it('says the ledger is shared and whose name is on a mark', async () => {
    mockLedger({})
    render(<ReviewLedgerPanel caseId={CASE} />)

    const panel = screen.getByRole('region', { name: /review ledger/i })
    await waitFor(() =>
      expect(panel.textContent).toMatch(/every examiner with access/i),
    )
    // The sentence this replaced said the ledger was browser-local. Once it is
    // shared that is a false reassurance, which is worse than the gap it
    // described, so nothing here may still say it.
    expect(panel.textContent).not.toMatch(/this browser/i)
    expect(panel.textContent).not.toMatch(/not shared/i)
    expect(panel.textContent).toMatch(/name of the examiner/i)
  })

  it('states the population is unknown rather than omitting the denominator', async () => {
    mockLedger({})
    render(<ReviewLedgerPanel caseId={CASE} />)
    const panel = screen.getByRole('region', { name: /review ledger/i })
    await waitFor(() =>
      expect(panel.textContent).toMatch(/population.*not stated/i),
    )
  })

  it('answers the handover question: who opened what, and when', async () => {
    mockLedger({
      opened: ['a', 'b'],
      reviewed: ['a'],
      examiners: [
        {
          examiner: 'alice',
          opened: 2,
          reviewed: 1,
          first_opened_at: 1_690_000_000,
          last_activity_at: 1_690_100_000,
        },
      ],
    })
    render(<ReviewLedgerPanel caseId={CASE} />)

    const row = await screen.findByRole('row', { name: /alice/i })
    expect(within(row).getByText('2')).toBeInTheDocument()
    expect(within(row).getByText('1')).toBeInTheDocument()
    expect(within(row).getByText(/2023-07-22 04:26:40 UTC/)).toBeInTheDocument()
    // The per-examiner columns and the case figures count different things and
    // the table has to say so, or a reader adds two examiners' 500s into 1,000
    // artifacts that were never examined.
    const table = row.closest('table')!
    expect(table.textContent).toMatch(/do not add up to the case figures/i)
  })

  it('says nobody has marked anything only once it has actually read', async () => {
    mockLedger({})
    render(<ReviewLedgerPanel caseId={CASE} />)
    const panel = screen.getByRole('region', { name: /review ledger/i })

    // Before the read lands the panel says it is reading. On a SHARED ledger
    // "no examiner has opened anything in this case" is a claim about every
    // examiner, and it must not be made out of an unfinished request.
    expect(panel.textContent).toMatch(/reading the case/i)
    await waitFor(() =>
      expect(panel.textContent).toMatch(/no examiner has opened or reviewed/i),
    )
  })

  it('says the listing was capped rather than letting rows read as unopened', async () => {
    mockLedger({ capped: true })
    render(<ReviewLedgerPanel caseId={CASE} />)

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/more marks than one listing returns/i)
    expect(alert.textContent).toMatch(/not a row nobody has opened/i)
  })

  it('says the ledger could not be read rather than showing an empty one', async () => {
    server.use(
      http.get('/api/v1/cases/:caseId/artifact_reviews/ids', () =>
        HttpResponse.json(
          { error: { code: 'JOB_FAILED', message: 'ledger unreachable' } },
          { status: 500 },
        ),
      ),
      http.get('/api/v1/cases/:caseId/artifact_reviews/stats', () =>
        HttpResponse.json(
          { error: { code: 'JOB_FAILED', message: 'ledger unreachable' } },
          { status: 500 },
        ),
      ),
    )
    render(<ReviewLedgerPanel caseId={CASE} />)

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/could not be read/i)

    // And the breakdown must not contradict it. A panel that said "no examiner
    // has opened or reviewed anything in this case" directly above "the
    // ledger could not be read" would offer a reader their choice of two
    // incompatible facts, and the false one is the reassuring one.
    const panel = screen.getByRole('region', { name: /review ledger/i })
    expect(panel.textContent).not.toMatch(/no examiner has opened/i)
    expect(panel.textContent).toMatch(/could not be read, so nothing here/i)
  })
})

describe('ReviewLedgerPanel, compact', () => {
  it('keeps the shared scope and the missing population on the line itself', async () => {
    mockLedger({})
    render(<ReviewLedgerPanel caseId={CASE} compact />)
    const panel = screen.getByRole('region', { name: /review ledger/i })
    const line = within(panel).getByText(
      /Review ledger \(this case\)/i,
    ).parentElement!

    // Neither qualification is allowed behind the disclosure: a reader who
    // never opens it must still not read these counts as a proportion of a
    // population nobody named, nor as this examiner's private record.
    expect(line.textContent).toMatch(/this case/i)
    expect(line.textContent).toMatch(/population not stated/i)
    expect(panel.textContent).not.toMatch(/%/)
  })

  it('still carries the full wording once the disclosure is opened', async () => {
    mockLedger({})
    const user = userEvent.setup()
    render(<ReviewLedgerPanel caseId={CASE} compact />)
    await user.click(screen.getByText(/what these counts do and do not say/i))

    const panel = screen.getByRole('region', { name: /review ledger/i })
    expect(panel.textContent).toMatch(/every examiner with access/i)
    expect(panel.textContent).toMatch(/opening is not examining/i)
  })
})

/**
 * The comms table renders one of these per row and its cap is five hundred
 * rows, so what a single mark costs is not a micro-optimisation: it is the
 * difference between a table that answers a click and one that hitches every
 * time an examiner marks a row. These cases pin the cost with a render count,
 * which is the only proxy a unit test has for it — and moving the ledger onto
 * the server must not quietly hand that property back.
 */
describe('ReviewMark at table scale', () => {
  const IDS = Array.from({ length: 40 }, (_, i) => `art-${i}`)

  async function renderRows() {
    const renders = new Map<string, number>()
    render(
      <>
        {IDS.map((id) => (
          <Profiler
            key={id}
            id={id}
            onRender={() => renders.set(id, (renders.get(id) ?? 0) + 1)}
          >
            <ReviewMark caseId={CASE} id={id} subject={`row ${id}`} />
          </Profiler>
        ))}
      </>,
    )
    // Wait for the case's listings to land before counting: the first read is
    // one repaint of every row and it is not what these cases are about.
    await screen.findAllByRole('button', { name: /^Mark row art-0 reviewed$/ })
    renders.clear()
    return renders
  }

  it('re-renders only the row that was marked, not every row on the table', async () => {
    mockLedger({})
    const user = userEvent.setup()
    const renders = await renderRows()

    await user.click(
      screen.getByRole('button', { name: /^Mark row art-7 reviewed$/ }),
    )
    await screen.findByRole('button', { name: /withdraw the review of row/i })

    // The marked row must repaint: it now says "Reviewed".
    expect(renders.get('art-7')).toBeGreaterThan(0)
    // Every other row's mark is unchanged, so nothing about it needs to be
    // drawn again. A ledger that woke all five hundred here would spend the
    // whole table's render budget on one row's click.
    expect([...renders.keys()].filter((id) => id !== 'art-7')).toEqual([])
  })

  it('still shows the mark it made, and shows it on the right row', async () => {
    mockLedger({})
    const user = userEvent.setup()
    await renderRows()

    await user.click(
      screen.getByRole('button', { name: /^Mark row art-7 reviewed$/ }),
    )

    // Cheaper must never mean staler. The row that was marked reads as marked
    // and no other row does — a row displaying someone else's mark is the
    // defect this ledger exists to prevent.
    const cleared = await screen.findByRole('button', {
      name: /reviewed by you — withdraw the review of row art-7/i,
    })
    expect(cleared).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getAllByRole('button', { name: /^Mark row/ })).toHaveLength(
      IDS.length - 1,
    )
  })

  it('asks the case once for the whole table, not once per row', async () => {
    let listings = 0
    mockLedger({})
    server.use(
      http.get('/api/v1/cases/:caseId/artifact_reviews/ids', () => {
        listings++
        return HttpResponse.json({
          ids: [],
          state: 'reviewed',
          examiner: null,
          scope: 'case',
          total: 0,
          returned: 0,
          capped: false,
          cap: 100_000,
        })
      }),
    )
    await renderRows()

    // Which artifacts have been reviewed is a fact about the CASE. Asking it
    // per row is what a four-million-artifact case cannot afford, and it is
    // the cost that put this ledger in the browser in the first place.
    expect(listings).toBeLessThanOrEqual(3)
  })
})

/**
 * A read that failed is recovered by an act of the examiner's.
 *
 * "Reload the page" is a poor answer to a panel that says it could not read the
 * ledger, and an automatic retry is a worse one: a read that succeeded unseen
 * would leave the screen asserting two different things minutes apart with
 * nothing the examiner could point to as the moment it changed. So the panel
 * offers the re-read, and reports the outcome as the outcome of what they did.
 */
describe('ReviewLedgerPanel, re-reading a ledger that could not be read', () => {
  function mockUnreadable(): { reads: number } {
    const counter = { reads: 0 }
    const fail = () => {
      counter.reads++
      return HttpResponse.json(
        { error: { code: 'JOB_FAILED', message: 'ledger unreachable' } },
        { status: 500 },
      )
    }
    server.use(
      http.get('/api/v1/cases/:caseId/artifact_reviews/ids', fail),
      http.get('/api/v1/cases/:caseId/artifact_reviews/stats', fail),
    )
    return counter
  }

  it('offers a re-read the examiner drives, and does not re-read on its own', async () => {
    const counter = mockUnreadable()
    const user = userEvent.setup()
    render(<ReviewLedgerPanel caseId={CASE} />)

    const retry = await screen.findByRole('button', {
      name: /read this case’s review ledger again/i,
    })
    const settled = counter.reads
    await new Promise((resolve) => setTimeout(resolve, 60))
    // Nothing happens until they ask. That is the point of the button.
    expect(counter.reads).toBe(settled)

    mockLedger({ opened: ['a', 'b'], reviewed: ['a'] })
    await user.click(retry)

    const panel = screen.getByRole('region', { name: /review ledger/i })
    // The refusal is gone because the ledger was read, not because the sentence
    // was tidied away. (The standing scope note mentions "could not be read" in
    // the abstract, so the assertion is against the alert's own wording.)
    await waitFor(() =>
      expect(panel.textContent).not.toMatch(
        /not a record of what has been examined/i,
      ),
    )
    expect(screen.queryByRole('alert')).toBeNull()
    expect(panel.textContent).toMatch(/re-read at .* because you asked/i)
    // And the three states the panel distinguishes survive the re-read: this
    // one came back empty of examiners, which is a real answer and is stated
    // as one rather than as the failure it replaced.
    expect(panel.textContent).toMatch(/no examiner has opened or reviewed/i)
  })

  it('says a re-read that failed again failed, rather than repeating itself', async () => {
    mockUnreadable()
    const user = userEvent.setup()
    render(<ReviewLedgerPanel caseId={CASE} />)

    const retry = await screen.findByRole('button', {
      name: /read this case’s review ledger again/i,
    })
    await user.click(retry)

    const panel = screen.getByRole('region', { name: /review ledger/i })
    await waitFor(() =>
      expect(panel.textContent).toMatch(/did not succeed either/i),
    )
    // Still not an empty ledger, and still not a zero.
    expect(panel.textContent).toMatch(/not a record of what has been examined/i)
    expect(panel.textContent).not.toMatch(/no examiner has opened or reviewed/i)
  })

  it('says it is re-reading while the re-read runs', async () => {
    mockUnreadable()
    let release: (() => void) | null = null
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    const user = userEvent.setup()
    render(<ReviewLedgerPanel caseId={CASE} />)
    const retry = await screen.findByRole('button', {
      name: /read this case’s review ledger again/i,
    })

    server.use(
      http.get('/api/v1/cases/:caseId/artifact_reviews/ids', async () => {
        await held
        return HttpResponse.json({
          ids: [],
          state: 'reviewed',
          examiner: null,
          scope: 'case',
          total: 0,
          returned: 0,
          capped: false,
          cap: 100_000,
        })
      }),
      http.get('/api/v1/cases/:caseId/artifact_reviews/stats', async () => {
        await held
        return HttpResponse.json({
          examiners: [],
          case: { opened: 0, reviewed: 0 },
          population: {
            total: 12,
            name: 'artifacts_in_case',
            label: 'every artifact recorded in this case, of every type',
            includes_non_reviewable_rows: true,
            exact: true,
          },
          reviewed_is_subset_of_opened: true,
          counts_are_distinct_artifacts: true,
        })
      }),
    )
    await user.click(retry)

    const panel = screen.getByRole('region', { name: /review ledger/i })
    // In flight is its own state, distinct from the empty ledger it may turn
    // out to be: the panel must not say "no examiner has opened anything"
    // while it is still finding out.
    await waitFor(() => expect(panel.textContent).toMatch(/re-reading/i))
    expect(panel.textContent).not.toMatch(/no examiner has opened or reviewed/i)

    release!()
    await waitFor(() =>
      expect(panel.textContent).toMatch(/no examiner has opened or reviewed/i),
    )
  })

  it('offers the re-read on the compact line too', async () => {
    mockUnreadable()
    render(<ReviewLedgerPanel caseId={CASE} compact />)
    expect(
      await screen.findByRole('button', {
        name: /read this case’s review ledger again/i,
      }),
    ).toBeInTheDocument()
  })

  it('offers no re-read when there is nothing wrong with the read', async () => {
    mockLedger({ opened: ['a'], reviewed: ['a'] })
    render(<ReviewLedgerPanel caseId={CASE} />)
    const panel = screen.getByRole('region', { name: /review ledger/i })
    await waitFor(() => expect(panel.textContent).toMatch(/1/))
    expect(
      screen.queryByRole('button', { name: /read this case.*again/i }),
    ).toBeNull()
  })
})

/**
 * Which colleague reviewed THIS row.
 *
 * The per-examiner panel says who has worked the case; on a case with two
 * colleagues it cannot say which of them reviewed this record, and that is the
 * question an examiner has when they are looking at the row. The name is read
 * from the row's own history when they ask for it, and never for a table full
 * of rows nobody asked about.
 */
describe('ReviewMark, naming the colleague who reviewed a row', () => {
  function mockHistory(
    examiners: string[],
    options: { hold?: Promise<void>; fail?: boolean } = {},
  ): { reads: number } {
    const counter = { reads: 0 }
    server.use(
      http.get(
        '/api/v1/cases/:caseId/artifact_reviews/history',
        async ({ request }) => {
          counter.reads++
          if (options.hold) await options.hold
          if (options.fail) {
            return HttpResponse.json(
              { error: { code: 'JOB_FAILED', message: 'history unavailable' } },
              { status: 500 },
            )
          }
          const wanted = new URL(request.url).searchParams.get('artifact_id')
          return HttpResponse.json({
            events: examiners.map((examiner, i) => ({
              artifact_id: wanted,
              examiner,
              action: 'reviewed',
              at: i + 1,
            })),
            artifact_id: wanted,
            examiner: null,
            returned: examiners.length,
            limit: 1000,
            capped: false,
          })
        },
      ),
    )
    return counter
  }

  it('names the examiner only when the row is asked about', async () => {
    mockLedger({ opened: ['art-1'], reviewed: ['art-1'], mine: [] })
    const counter = mockHistory(['bob'])
    const user = userEvent.setup()
    render(<ReviewMark caseId={CASE} id="art-1" subject="row 1" />)

    const ask = await screen.findByRole('button', {
      name: /read which examiner reviewed row 1/i,
    })
    // Rendering a row is not asking about it. At five hundred rows this is the
    // difference between one request and five hundred.
    expect(counter.reads).toBe(0)
    expect(ask.textContent).toMatch(/reviewed by another examiner/i)

    await user.click(ask)
    expect(await screen.findByText(/reviewed by bob/i)).toBeInTheDocument()
    expect(counter.reads).toBe(1)
    // Naming the reviewer does not turn their review into yours.
    expect(
      screen.getByRole('button', { name: /^Mark row 1 reviewed/ }),
    ).toHaveAttribute('aria-pressed', 'false')
  })

  it('names every examiner who holds a review, not just one', async () => {
    mockLedger({ opened: ['art-1'], reviewed: ['art-1'], mine: [] })
    mockHistory(['carol', 'bob'])
    const user = userEvent.setup()
    render(<ReviewMark caseId={CASE} id="art-1" subject="row 1" />)

    await user.click(
      await screen.findByRole('button', {
        name: /read which examiner reviewed row 1/i,
      }),
    )
    expect(await screen.findByText(/reviewed by bob and carol/i)).toBeVisible()
  })

  it('names nobody while the name is still being read', async () => {
    mockLedger({ opened: ['art-1'], reviewed: ['art-1'], mine: [] })
    let release: (() => void) | null = null
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    mockHistory(['bob'], { hold: held })
    const user = userEvent.setup()
    render(<ReviewMark caseId={CASE} id="art-1" subject="row 1" />)

    await user.click(
      await screen.findByRole('button', {
        name: /read which examiner reviewed row 1/i,
      }),
    )
    // Half an answer is not an answer: no name, and nothing that reads as
    // "nobody", while the history is in flight.
    const reading = await screen.findByText(/reading who/i)
    expect(reading.textContent).not.toMatch(/bob/i)
    expect(reading.textContent).not.toMatch(/nobody/i)

    release!()
    expect(await screen.findByText(/reviewed by bob/i)).toBeInTheDocument()
  })

  it('says the name could not be read rather than dropping the qualification', async () => {
    mockLedger({ opened: ['art-1'], reviewed: ['art-1'], mine: [] })
    mockHistory([], { fail: true })
    const user = userEvent.setup()
    render(<ReviewMark caseId={CASE} id="art-1" subject="row 1" />)

    await user.click(
      await screen.findByRole('button', {
        name: /read which examiner reviewed row 1/i,
      }),
    )

    // The review still stands; only its author is unread. Saying so keeps the
    // row from reading as though nobody had reviewed it.
    expect(
      await screen.findByText(/reviewed by another examiner/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/could not be read/i)).toBeInTheDocument()
  })

  it('does not offer a name for a row that carries no review', async () => {
    mockLedger({ opened: ['art-1'] })
    render(<ReviewMark caseId={CASE} id="art-1" subject="row 1" />)

    expect(await screen.findByText(/^opened$/i)).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /read which examiner reviewed/i }),
    ).toBeNull()
  })
})

/**
 * A name is an attribution, and an attribution carries a date.
 *
 * The row reads who holds the review once, when the examiner asks. Nothing
 * refreshes it and nothing expires it — both would change the screen at a
 * moment the examiner cannot account for. Instead the row says when it read
 * what it is showing, and offers to read it again.
 */
describe('ReviewMark, saying when the name on the row was read', () => {
  const STAMP = /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/

  /** History a test can change between one reading and the next. */
  function mockHistoryState(state: {
    examiners: string[]
    fail?: boolean
    hold?: Promise<void>
  }): { reads: number } {
    const counter = { reads: 0 }
    server.use(
      http.get(
        '/api/v1/cases/:caseId/artifact_reviews/history',
        async ({ request }) => {
          counter.reads++
          if (state.hold) await state.hold
          if (state.fail) {
            return HttpResponse.json(
              { error: { code: 'JOB_FAILED', message: 'history unavailable' } },
              { status: 500 },
            )
          }
          const wanted = new URL(request.url).searchParams.get('artifact_id')
          return HttpResponse.json({
            events: state.examiners.map((examiner, i) => ({
              artifact_id: wanted,
              examiner,
              action: 'reviewed',
              at: i + 1,
            })),
            artifact_id: wanted,
            examiner: null,
            returned: state.examiners.length,
            limit: 1000,
            capped: false,
          })
        },
      ),
    )
    return counter
  }

  async function askAboutRow() {
    const user = userEvent.setup()
    render(<ReviewMark caseId={CASE} id="art-1" subject="row 1" />)
    await user.click(
      await screen.findByRole('button', {
        name: /read which examiner reviewed row 1/i,
      }),
    )
    return user
  }

  it('dates the name it shows, and offers to read it again', async () => {
    mockLedger({ opened: ['art-1'], reviewed: ['art-1'], mine: [] })
    const counter = mockHistoryState({ examiners: ['bob'] })
    await askAboutRow()

    expect(await screen.findByText(/reviewed by bob/i)).toBeInTheDocument()
    // The name without its date cannot be told apart from a name read an hour
    // ago, which is the whole reason the date is on screen and not in a
    // tooltip.
    const again = screen.getByRole('button', { name: /read it again/i })
    expect(again.textContent).toMatch(STAMP)
    expect(counter.reads).toBe(1)
  })

  it('takes a second reading when the examiner asks for one, and says what changed', async () => {
    mockLedger({ opened: ['art-1'], reviewed: ['art-1'], mine: [] })
    const state = { examiners: ['bob'] }
    const counter = mockHistoryState(state)
    const user = await askAboutRow()
    expect(await screen.findByText(/reviewed by bob/i)).toBeInTheDocument()

    // bob withdraws and carol reviews. Nothing on screen may learn that by
    // itself; the examiner asks, and the answer is the answer to their asking.
    state.examiners = ['carol']
    await user.click(screen.getByRole('button', { name: /read it again/i }))

    expect(await screen.findByText(/reviewed by carol/i)).toBeInTheDocument()
    expect(counter.reads).toBe(2)
    // An examiner who quoted "bob" needs to be able to account for it, so the
    // change is an event with both names and the earlier reading's time.
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/bob/)
    expect(alert.textContent).toMatch(/carol/)
    expect(alert.textContent).toMatch(STAMP)
  })

  it('keeps the name it has while it reads again', async () => {
    mockLedger({ opened: ['art-1'], reviewed: ['art-1'], mine: [] })
    const state: { examiners: string[]; hold?: Promise<void> } = {
      examiners: ['bob'],
    }
    mockHistoryState(state)
    const user = await askAboutRow()
    expect(await screen.findByText(/reviewed by bob/i)).toBeInTheDocument()

    let release: (() => void) | null = null
    state.hold = new Promise<void>((resolve) => {
      release = resolve
    })
    state.examiners = ['carol']
    await user.click(screen.getByRole('button', { name: /read it again/i }))

    // What the row read is still what the row knows. Blanking it mid-reading
    // would leave the row saying nothing about a review it has attributed.
    expect(screen.getByText(/reviewed by bob/i)).toBeInTheDocument()
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /reading again/i })).toHaveAttribute(
        'aria-busy',
        'true',
      ),
    )

    release!()
    expect(await screen.findByText(/reviewed by carol/i)).toBeInTheDocument()
  })

  it('says a second reading failed without dropping the first', async () => {
    mockLedger({ opened: ['art-1'], reviewed: ['art-1'], mine: [] })
    const state: { examiners: string[]; fail?: boolean } = {
      examiners: ['bob'],
    }
    mockHistoryState(state)
    const user = await askAboutRow()
    expect(await screen.findByText(/reviewed by bob/i)).toBeInTheDocument()

    state.fail = true
    await user.click(screen.getByRole('button', { name: /read it again/i }))

    // A reading that failed is not evidence that the earlier one was wrong.
    await waitFor(() =>
      expect(
        screen.getByText(/reviewed by bob/i).textContent,
      ).toMatch(/did not complete/i),
    )
    expect(screen.getByText(/reviewed by bob/i)).toBeInTheDocument()
  })
})

/**
 * A re-read that recovered one response must not look like a re-read of four.
 *
 * Narrowing the retry is what makes it affordable on a case at the listing
 * ceiling. The price is that the panel afterwards holds one fresh figure and
 * three older ones, and it has to say which is which.
 */
describe('ReviewLedgerPanel, a re-read that covered part of the ledger', () => {
  interface Parts {
    openedFails?: boolean
    statsFails?: boolean
    opened?: string[]
    reviewed?: string[]
  }

  function mockParts(fixture: Parts) {
    const reads = { ids: 0, stats: 0 }
    const fail = (what: string) =>
      HttpResponse.json(
        { error: { code: 'JOB_FAILED', message: `${what} unavailable` } },
        { status: 500 },
      )
    server.use(
      http.get('/api/v1/cases/:caseId/artifact_reviews/ids', ({ request }) => {
        reads.ids++
        const params = new URL(request.url).searchParams
        const which = params.get('state') ?? 'reviewed'
        const examiner = params.get('examiner')
        if (which === 'opened' && !examiner && fixture.openedFails)
          return fail('the opened listing')
        const ids = examiner
          ? []
          : which === 'opened'
            ? (fixture.opened ?? [])
            : (fixture.reviewed ?? [])
        return HttpResponse.json({
          ids,
          state: which,
          examiner,
          scope: examiner ? 'examiner' : 'case',
          total: ids.length,
          returned: ids.length,
          capped: false,
          cap: 100_000,
        })
      }),
      http.get('/api/v1/cases/:caseId/artifact_reviews/stats', () => {
        reads.stats++
        if (fixture.statsFails) return fail('the roll-up')
        return HttpResponse.json({
          examiners: [
            {
              examiner: 'alice',
              opened: 2,
              reviewed: 1,
              first_opened_at: 1_690_000_000,
              last_activity_at: 1_690_100_000,
            },
          ],
          case: {
            opened: (fixture.opened ?? []).length,
            reviewed: (fixture.reviewed ?? []).length,
          },
          population: {
            total: 4_012_345,
            name: 'artifacts_in_case',
            label: 'every artifact recorded in this case, of every type',
            includes_non_reviewable_rows: true,
            exact: true,
          },
          reviewed_is_subset_of_opened: true,
          counts_are_distinct_artifacts: true,
        })
      }),
    )
    return reads
  }

  it('names what the re-read covered and dates what it did not', async () => {
    const fixture: Parts = {
      opened: ['a', 'b'],
      reviewed: ['a'],
      statsFails: true,
    }
    const reads = mockParts(fixture)
    const user = userEvent.setup()
    render(<ReviewLedgerPanel caseId={CASE} />)

    const retry = await screen.findByRole('button', {
      name: /read this case’s review ledger again/i,
    })
    const listings = reads.ids
    fixture.statsFails = false
    await user.click(retry)

    const panel = screen.getByRole('region', { name: /review ledger/i })
    await waitFor(() =>
      expect(panel.textContent).toMatch(/re-read at .* because you asked/i),
    )
    // The two listings were not re-fetched. On a case at the ceiling that is
    // two hundred thousand ids the examiner did not wait for.
    expect(reads.ids).toBe(listings)
    // And because they were not, the panel says so rather than presenting one
    // fresh figure and three older ones as one reading.
    expect(panel.textContent).toMatch(/per-examiner roll-up/i)
    expect(panel.textContent).toMatch(/list of opened records/i)
    expect(panel.textContent).toMatch(
      /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/,
    )
  })

  it('does not call the whole ledger unread when one response failed', async () => {
    mockParts({ opened: ['a', 'b'], reviewed: ['a'], openedFails: true })
    render(<ReviewLedgerPanel caseId={CASE} />)

    const panel = screen.getByRole('region', { name: /review ledger/i })
    // The roll-up came back, so the counts are real and the handover table
    // still answers. Saying "the ledger could not be read" over figures that
    // were read is a false absence of its own.
    await waitFor(() => expect(panel.textContent).toMatch(/alice/))
    expect(panel.textContent).toMatch(/part of the case’s review ledger/i)
    expect(panel.textContent).toMatch(/list of opened records/i)
    expect(panel.textContent).not.toMatch(
      /who has examined what could not be read/i,
    )
  })
})
