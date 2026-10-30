import { act, renderHook, waitFor } from '@testing-library/react'
import { HttpResponse, http } from 'msw'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { server } from '../test/server'
import {
  OPENING_FLUSH_MS,
  resetReviewLedger,
  reviewLedgerWriter,
  useReviewEntry,
  useReviewLedger,
  useReviewLedgerWriter,
} from './useReviewed'

const CASE = 'c1a5e000-0000-4000-8000-000000000001'
const OTHER_CASE = 'c1a5e000-0000-4000-8000-000000000002'
const A = 'aaaaaaaa-0000-4000-8000-000000000001'
const B = 'bbbbbbbb-0000-4000-8000-000000000002'

/** One POST body as the server received it, so a test can count requests. */
interface SentBatch {
  marks: { artifact_id: string; state: string }[]
}

const posted: SentBatch[] = []

interface LedgerFixture {
  opened?: string[]
  reviewed?: string[]
  mine?: string[]
  openedCapped?: boolean
  reviewedCapped?: boolean
  examiners?: {
    examiner: string
    opened: number
    reviewed: number
    first_opened_at: number
    last_activity_at: number
  }[]
  caseOpened?: number
  caseReviewed?: number
  population?: number
}

/**
 * The whole ledger family, answered from a fixture.
 *
 * Every test states the responses it expects rather than inheriting them: msw
 * runs with `onUnhandledRequest: 'error'` here precisely so a request nobody
 * intended cannot be absorbed silently.
 */
function mockLedger(fixture: LedgerFixture = {}) {
  const opened = fixture.opened ?? []
  const reviewed = fixture.reviewed ?? []
  const mine = fixture.mine ?? []

  server.use(
    http.get('/api/v1/cases/:caseId/artifact_reviews/ids', ({ request }) => {
      const params = new URL(request.url).searchParams
      const state = params.get('state')
      const examiner = params.get('examiner')
      const ids = examiner ? mine : state === 'opened' ? opened : reviewed
      const capped =
        state === 'opened'
          ? (fixture.openedCapped ?? false)
          : (fixture.reviewedCapped ?? false)
      return HttpResponse.json({
        ids,
        state: state ?? 'reviewed',
        examiner,
        scope: examiner ? 'examiner' : 'case',
        total: capped ? ids.length + 7 : ids.length,
        returned: ids.length,
        capped,
        cap: 100000,
      })
    }),
    http.get('/api/v1/cases/:caseId/artifact_reviews/stats', () =>
      HttpResponse.json({
        examiners: fixture.examiners ?? [],
        case: {
          opened: fixture.caseOpened ?? opened.length,
          reviewed: fixture.caseReviewed ?? reviewed.length,
        },
        population: {
          total: fixture.population ?? 4_012_345,
          name: 'artifacts_in_case',
          label: 'every artifact recorded in this case, of every type',
          includes_non_reviewable_rows: true,
          exact: true,
        },
        reviewed_is_subset_of_opened: true,
        counts_are_distinct_artifacts: true,
      }),
    ),
  )
}

/** The POST, answering with the transition counts a real batch would report. */
function mockPost(
  responder?: (body: SentBatch) => Record<string, unknown> | Response,
) {
  server.use(
    http.post('/api/v1/cases/:caseId/artifact_reviews', async ({ request }) => {
      const body = (await request.json()) as SentBatch
      posted.push(body)
      const custom = responder?.(body)
      if (custom instanceof Response) return custom
      return HttpResponse.json({
        examiner: 'local',
        received: body.marks.length,
        openings_recorded: body.marks.length,
        reviews_recorded: 0,
        reviews_withdrawn: 0,
        unchanged: 0,
        rejected: [],
        rejected_reason: 'artifact_not_in_case',
        batch_max: 1000,
        ...custom,
      })
    }),
  )
}

beforeEach(() => {
  posted.length = 0
  localStorage.clear()
  resetReviewLedger()
})

afterEach(() => {
  resetReviewLedger()
})

describe('the ledger is the case’s, not this browser’s', () => {
  it('shows an examiner what somebody else already opened and reviewed', async () => {
    // The handover, which is the whole point: nothing was marked in THIS
    // browser, and the ledger is not empty.
    mockLedger({
      opened: [A, B],
      reviewed: [A],
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
    const { result } = renderHook(() => useReviewLedger(CASE))

    await waitFor(() => expect(result.current.loaded).toBe(true))
    expect(result.current.counts).toEqual({ opened: 2, reviewed: 1 })
    expect(result.current.examiners[0]).toMatchObject({
      examiner: 'alice',
      opened: 2,
      reviewed: 1,
    })
    // Two claims, two counts, and the population named rather than divided by.
    expect(result.current.population).toMatchObject({
      total: 4_012_345,
      name: 'artifacts_in_case',
      includesNonReviewableRows: true,
    })
  })

  it('keeps opening and reviewing as two separate claims about one row', async () => {
    mockLedger({ opened: [A, B], reviewed: [A] })
    const marked = renderHook(() => useReviewEntry(CASE, A))
    const openedOnly = renderHook(() => useReviewEntry(CASE, B))

    await waitFor(() => expect(marked.result.current.reviewed).toBe(true))
    expect(marked.result.current.opened).toBe(true)
    // Opened is not reviewed. If this ever became true, a scroll-past would be
    // admissible as evidence that the row was examined.
    expect(openedOnly.result.current.opened).toBe(true)
    expect(openedOnly.result.current.reviewed).toBe(false)
  })

  it('keeps one case’s marks out of another case’s ledger', async () => {
    mockLedger({ opened: [A], reviewed: [A] })
    const here = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(here.result.current.reviewed).toBe(true))

    server.resetHandlers()
    mockLedger({})
    const there = renderHook(() => useReviewEntry(OTHER_CASE, A))
    await waitFor(() => expect(there.result.current.reviewed).toBe(false))
    expect(here.result.current.reviewed).toBe(true)
  })
})

describe('what has not been read is never drawn as what has', () => {
  it('reports every row as not known until the listing lands', () => {
    mockLedger({ reviewed: [A] })
    const { result } = renderHook(() => useReviewEntry(CASE, A))
    // The first frame, before anything answered. `false` here would tell an
    // examiner that nobody on the case has examined this record, out of nothing
    // but a request that has not returned.
    expect(result.current.opened).toBeNull()
    expect(result.current.reviewed).toBeNull()
  })

  it('reports rows past the listing’s ceiling as not known, not as unopened', async () => {
    mockLedger({
      opened: [A],
      reviewed: [A],
      openedCapped: true,
      reviewedCapped: true,
    })
    const listed = renderHook(() => useReviewEntry(CASE, A))
    const beyond = renderHook(() => useReviewEntry(CASE, B))
    const ledger = renderHook(() => useReviewLedger(CASE))

    await waitFor(() => expect(listed.result.current.reviewed).toBe(true))
    // B is simply not in a list that stopped short, which establishes nothing
    // about B. Painting it unopened would be a false absence across every row
    // past the ceiling — the failure this whole feature exists to prevent.
    expect(beyond.result.current.opened).toBeNull()
    expect(beyond.result.current.reviewed).toBeNull()
    expect(ledger.result.current.idsCapped).toBe(true)
  })

  it('treats a ledger that could not be read as unknown, not as empty', async () => {
    server.use(
      http.get('/api/v1/cases/:caseId/artifact_reviews/ids', () =>
        HttpResponse.json(
          { error: { code: 'JOB_FAILED', message: 'ledger unreadable' } },
          { status: 500 },
        ),
      ),
      http.get('/api/v1/cases/:caseId/artifact_reviews/stats', () =>
        HttpResponse.json(
          { error: { code: 'JOB_FAILED', message: 'ledger unreadable' } },
          { status: 500 },
        ),
      ),
    )
    const ledger = renderHook(() => useReviewLedger(CASE))
    const row = renderHook(() => useReviewEntry(CASE, A))

    await waitFor(() => expect(ledger.result.current.loadError).toBeTruthy())
    // Not zero. Zero is a statement about the case; this is a statement about
    // a request that failed.
    expect(ledger.result.current.counts).toEqual({
      opened: null,
      reviewed: null,
    })
    expect(row.result.current.reviewed).toBeNull()
    expect(ledger.result.current.loadError).toMatch(
      /not a record of what has been examined/i,
    )
  })
})

describe('nothing is shown that was not recorded', () => {
  it('does not show a review until the server has taken it', async () => {
    mockLedger({})
    let release: (() => void) | null = null
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    mockPost(() => {
      throw new Error('unused')
    })
    server.use(
      http.post('/api/v1/cases/:caseId/artifact_reviews', async () => {
        await held
        return HttpResponse.json({
          examiner: 'local',
          received: 1,
          openings_recorded: 1,
          reviews_recorded: 1,
          reviews_withdrawn: 0,
          unchanged: 0,
          rejected: [],
          rejected_reason: 'artifact_not_in_case',
          batch_max: 1000,
        })
      }),
    )

    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewed).toBe(false))

    const writer = reviewLedgerWriter(CASE)
    let settled: Promise<void>
    act(() => {
      settled = writer.markReviewed(A)
    })

    // In flight: the row says a mark is BEING recorded, which is a different
    // claim from the mark. A frame showing the review here would be a frame
    // that could be screenshotted and would not survive a reload.
    await waitFor(() => expect(row.result.current.pending).toBe('reviewed'))
    expect(row.result.current.reviewed).toBe(false)
    // `false`, and not "not known", even though this browser has no session
    // record and so has not been told which examiner it files marks under. It
    // does not need to be: the case-wide listing says NOBODY holds a review of
    // this row, and whoever you are, you are one of the nobodies. The identity
    // only matters when a review does exist and the question is whose.
    expect(row.result.current.reviewedByMe).toBe(false)

    await act(async () => {
      release!()
      await settled!
    })
    expect(row.result.current.reviewed).toBe(true)
    expect(row.result.current.reviewedByMe).toBe(true)
    // Recording a review records an opening too — at the instant it happened.
    expect(row.result.current.opened).toBe(true)
  })

  it('says a review was refused rather than dropping it silently', async () => {
    mockLedger({})
    server.use(
      http.post('/api/v1/cases/:caseId/artifact_reviews', () =>
        HttpResponse.json(
          {
            error: { code: 'JOB_FAILED', message: 'the ledger is unavailable' },
          },
          { status: 500 },
        ),
      ),
    )
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewed).toBe(false))

    await act(async () => {
      await reviewLedgerWriter(CASE).markReviewed(A)
    })

    expect(row.result.current.reviewed).toBe(false)
    expect(row.result.current.error).toMatch(/was not recorded/i)
    expect(row.result.current.pending).toBeNull()
  })

  it('says an artifact the case does not hold was refused', async () => {
    mockLedger({})
    mockPost(() => ({ rejected: [A], openings_recorded: 0 }))
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewed).toBe(false))

    await act(async () => {
      await reviewLedgerWriter(CASE).markReviewed(A)
    })

    expect(row.result.current.reviewed).toBe(false)
    expect(row.result.current.error).toMatch(/does not hold this artifact/i)
  })
})

describe('openings arrive in bursts and are sent as one', () => {
  it('gathers a burst of openings into a single request', async () => {
    mockLedger({})
    mockPost()
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loaded).toBe(true))

    const writer = reviewLedgerWriter(CASE)
    act(() => {
      writer.markOpened(A)
      writer.markOpened(B)
    })

    await waitFor(() => expect(posted).toHaveLength(1))
    // One request for the burst, not one per row. A request per opening is the
    // cost that drove this ledger into the browser in the first place.
    expect(posted[0].marks).toHaveLength(2)
    expect(posted[0].marks.every((m) => m.state === 'opened')).toBe(true)
  })

  it('does not re-send an opening it has already recorded', async () => {
    mockLedger({})
    mockPost()
    const writer = reviewLedgerWriter(CASE)
    renderHook(() => useReviewLedger(CASE))

    act(() => writer.markOpened(A))
    await waitFor(() => expect(posted).toHaveLength(1))
    act(() => writer.markOpened(A))
    await act(async () => {
      await writer.flushOpenings()
    })
    expect(posted).toHaveLength(1)
  })

  it('sends what it has gathered when the tab goes away', async () => {
    mockLedger({})
    mockPost()
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loaded).toBe(true))

    act(() => reviewLedgerWriter(CASE).markOpened(A))
    act(() => {
      window.dispatchEvent(new Event('pagehide'))
    })

    // Well inside the gathering window: the timer has not fired and would not
    // for another OPENING_FLUSH_MS, so this passes only because closing the tab
    // sends what was gathered rather than dropping it unremarked.
    await waitFor(() => expect(posted).toHaveLength(1), {
      timeout: OPENING_FLUSH_MS - 100,
    })
    expect(posted[0].marks).toEqual([{ artifact_id: A, state: 'opened' }])
  })

  it('says how many openings were lost when the batch could not be sent', async () => {
    mockLedger({})
    server.use(
      http.post('/api/v1/cases/:caseId/artifact_reviews', () =>
        HttpResponse.json(
          {
            error: { code: 'JOB_FAILED', message: 'the ledger is unavailable' },
          },
          { status: 500 },
        ),
      ),
    )
    const ledger = renderHook(() => useReviewLedger(CASE))
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(ledger.result.current.loaded).toBe(true))

    const writer = reviewLedgerWriter(CASE)
    act(() => {
      writer.markOpened(A)
      writer.markOpened(B)
    })
    await act(async () => {
      await writer.flushOpenings()
    })

    // A dropped opening that says nothing is the one behaviour ruled out: the
    // examiner would go on believing the case holds a record of what they read.
    expect(ledger.result.current.writeError).toMatch(
      /2 openings were not recorded/i,
    )
    expect(row.result.current.opened).toBe(false)
    expect(ledger.result.current.unrecorded).toBe(0)
  })

  /**
   * The banner says what the ledger is SHORT of now, not what once went wrong.
   *
   * `writeError` used to be assigned at each failure and cleared nowhere, so a
   * single dropped request left "A review could not be recorded on the server."
   * standing in a `role="alert"` banner for the life of the ledger — through
   * every successful write that followed. An examiner who marks a record
   * reviewed and sees that banner beside the mark they just made is being told,
   * falsely, that it was not recorded. `loadError` was always derived from
   * standing state; this is the write side held to the same rule.
   */
  it('retires the write banner when the work it describes is made good', async () => {
    mockLedger({})
    let failing = true
    server.use(
      http.post('/api/v1/cases/:caseId/artifact_reviews', async ({ request }) => {
        if (failing) {
          return HttpResponse.json(
            { error: { code: 'JOB_FAILED', message: 'the ledger is unavailable' } },
            { status: 500 },
          )
        }
        const body = (await request.json()) as SentBatch
        const marks = body.marks ?? []
        return HttpResponse.json({
          examiner: 'local',
          received: marks.length,
          openings_recorded: marks.filter((m) => m.state === 'opened').length,
          reviews_recorded: marks.filter((m) => m.state === 'reviewed').length,
          reviews_withdrawn: 0,
          unchanged: 0,
          rejected: [],
          rejected_reason: 'artifact_not_in_case',
        })
      }),
    )
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loaded).toBe(true))
    const writer = reviewLedgerWriter(CASE)

    // One opening fails.
    act(() => {
      writer.markOpened(A)
    })
    await act(async () => {
      await writer.flushOpenings()
    })
    expect(ledger.result.current.writeError).toMatch(/1 opening was not recorded/i)

    // The server comes back and the examiner opens that same record again. The
    // opening IS on the server now, so the sentence about it must go.
    failing = false
    act(() => {
      writer.markOpened(A)
    })
    await act(async () => {
      await writer.flushOpenings()
    })
    expect(ledger.result.current.writeError).toBeNull()

    // And a review that fails, then succeeds, behaves the same way — this is the
    // path that latched the permanent "A review could not be recorded" sentence.
    failing = true
    await act(async () => {
      await writer.markReviewed(B)
    })
    expect(ledger.result.current.writeError).toMatch(/1 review could not be written/i)

    failing = false
    await act(async () => {
      await writer.markReviewed(B)
    })
    expect(
      ledger.result.current.writeError,
      'a review that succeeded on retry must not leave a banner saying it failed',
    ).toBeNull()
  })

  /**
   * Two records failing for two different reasons are two different sentences,
   * and making one good must not retire the other.
   */
  it('keeps the part of the write gap that is still standing', async () => {
    mockLedger({})
    let mode: 'fail' | 'reject' | 'ok' = 'fail'
    server.use(
      http.post('/api/v1/cases/:caseId/artifact_reviews', async ({ request }) => {
        if (mode === 'fail') {
          return HttpResponse.json(
            { error: { code: 'JOB_FAILED', message: 'the ledger is unavailable' } },
            { status: 500 },
          )
        }
        const body = (await request.json()) as SentBatch
        const marks = body.marks ?? []
        const rejected = mode === 'reject' ? marks.map((m) => m.artifact_id) : []
        return HttpResponse.json({
          examiner: 'local',
          received: marks.length,
          openings_recorded: marks.length - rejected.length,
          reviews_recorded: 0,
          reviews_withdrawn: 0,
          unchanged: 0,
          rejected,
          rejected_reason: 'artifact_not_in_case',
        })
      }),
    )
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loaded).toBe(true))
    const writer = reviewLedgerWriter(CASE)

    // A is not held in this case: a standing fact, not a transient failure.
    mode = 'reject'
    act(() => {
      writer.markOpened(A)
    })
    await act(async () => {
      await writer.flushOpenings()
    })
    expect(ledger.result.current.writeError).toMatch(/1 record is not held in this case/i)

    // B's opening then fails to send. Both clauses must now stand.
    mode = 'fail'
    act(() => {
      writer.markOpened(B)
    })
    await act(async () => {
      await writer.flushOpenings()
    })
    expect(ledger.result.current.writeError).toMatch(/1 opening was not recorded/i)
    expect(ledger.result.current.writeError).toMatch(/not held in this case/i)

    // B is recorded on retry. A is still not in the case, and that must survive.
    mode = 'ok'
    act(() => {
      writer.markOpened(B)
    })
    await act(async () => {
      await writer.flushOpenings()
    })
    expect(ledger.result.current.writeError).not.toMatch(/opening was not recorded/i)
    expect(
      ledger.result.current.writeError,
      'making one failure good must not retire a different one that still stands',
    ).toMatch(/1 record is not held in this case/i)
  })

  it('counts a gathered mark once, not once per structure holding it', async () => {
    mockLedger({})
    let release: (() => void) | null = null
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    server.use(
      http.post('/api/v1/cases/:caseId/artifact_reviews', async () => {
        await held
        return HttpResponse.json({
          examiner: 'local',
          received: 1,
          openings_recorded: 1,
          reviews_recorded: 0,
          reviews_withdrawn: 0,
          unchanged: 0,
          rejected: [],
          rejected_reason: 'artifact_not_in_case',
          batch_max: 1000,
        })
      }),
    )
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loaded).toBe(true))

    act(() => reviewLedgerWriter(CASE).markOpened(A))

    // One opening is one unrecorded mark. This figure is printed on screen as
    // "N marks are still being recorded"; a queue and a pending map that both
    // hold the id must not make it two.
    await waitFor(() => expect(ledger.result.current.unrecorded).toBe(1))
    await act(async () => {
      release!()
      await reviewLedgerWriter(CASE).flushOpenings()
    })
    expect(ledger.result.current.unrecorded).toBe(0)
  })
})

describe('a shared ledger means a review may not be yours to withdraw', () => {
  it('tells the examiner when the review on a row belongs to somebody else', async () => {
    // Reviewed case-wide, and NOT in this examiner's own list.
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({ opened: [A], reviewed: [A], mine: [] })
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewed).toBe(true))
    expect(row.result.current.reviewedByMe).toBe(false)

    mockPost(() => ({ examiner: 'bob', reviews_withdrawn: 0, unchanged: 1 }))
    await act(async () => {
      await reviewLedgerWriter(CASE).unmarkReviewed(A)
    })

    // The row still carries alice's review, and the screen says so rather than
    // showing a control that appears to have done nothing.
    expect(row.result.current.reviewed).toBe(true)
    expect(row.result.current.error).toMatch(/another examiner/i)
  })

  it('re-reads the row from its history when a withdrawal succeeds', async () => {
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({ opened: [A], reviewed: [A], mine: [A] })
    mockPost(() => ({ examiner: 'bob', reviews_withdrawn: 1 }))
    server.use(
      http.get('/api/v1/cases/:caseId/artifact_reviews/history', () =>
        HttpResponse.json({
          events: [
            { artifact_id: A, examiner: 'alice', action: 'opened', at: 1 },
            { artifact_id: A, examiner: 'alice', action: 'reviewed', at: 2 },
            { artifact_id: A, examiner: 'bob', action: 'reviewed', at: 3 },
            {
              artifact_id: A,
              examiner: 'bob',
              action: 'review_withdrawn',
              at: 4,
            },
          ],
          artifact_id: A,
          examiner: null,
          returned: 4,
          limit: 1000,
          capped: false,
        }),
      ),
    )
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewedByMe).toBe(true))

    await act(async () => {
      await reviewLedgerWriter(CASE).unmarkReviewed(A)
    })

    // Bob's review is gone; alice's still stands. The case-wide id listing
    // cannot tell those apart — it says "somebody" — so the row is re-read from
    // the append-only history, which can.
    expect(row.result.current.reviewedByMe).toBe(false)
    expect(row.result.current.reviewed).toBe(true)
    expect(row.result.current.opened).toBe(true)
  })

  it('says the row’s state is not known when the re-read fails', async () => {
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({ opened: [A], reviewed: [A], mine: [A] })
    mockPost(() => ({ examiner: 'bob', reviews_withdrawn: 1 }))
    server.use(
      http.get('/api/v1/cases/:caseId/artifact_reviews/history', () =>
        HttpResponse.json(
          { error: { code: 'JOB_FAILED', message: 'history unavailable' } },
          { status: 500 },
        ),
      ),
    )
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewedByMe).toBe(true))

    await act(async () => {
      await reviewLedgerWriter(CASE).unmarkReviewed(A)
    })

    expect(row.result.current.reviewed).toBeNull()
    expect(row.result.current.error).toMatch(/could not be re-read/i)
  })

  it('adopts the examiner name the server files marks under', async () => {
    // No session record at all, which is what a build with authentication
    // disabled looks like; the API attributes everything to "local".
    mockLedger({ opened: [], reviewed: [], mine: [A] })
    mockPost(() => ({ examiner: 'local', reviews_recorded: 1 }))
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loaded).toBe(true))
    expect(ledger.result.current.examiner).toBeNull()

    await act(async () => {
      await reviewLedgerWriter(CASE).markReviewed(B)
    })

    await waitFor(() => expect(ledger.result.current.examiner).toBe('local'))
    // And now that it knows whose marks are whose, it re-reads its own list
    // rather than going on saying "not known".
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewedByMe).toBe(true))
  })
})

/** A promise the test releases by hand, so a request can be held in flight. */
function gate(): { wait: Promise<void>; open: () => void } {
  let open: () => void = () => {}
  const wait = new Promise<void>((resolve) => {
    open = resolve
  })
  return { wait, open }
}

describe('a read that was overtaken does not overwrite what overtook it', () => {
  it('keeps the identity a write established while the first read was in flight', async () => {
    // The browser's session record says "alice"; the server files marks under
    // "local" (authentication disabled). The FIRST read of "which reviews are
    // mine" is asked under the guessed name and is slow to answer.
    localStorage.setItem(
      'seance_session',
      JSON.stringify({ username: 'alice' }),
    )
    const aliceRead = gate()
    server.use(
      http.get(
        '/api/v1/cases/:caseId/artifact_reviews/ids',
        async ({ request }) => {
          const params = new URL(request.url).searchParams
          const examiner = params.get('examiner')
          if (examiner === 'alice') await aliceRead.wait
          const ids = examiner === 'local' ? [A] : []
          return HttpResponse.json({
            ids,
            state: params.get('state') ?? 'reviewed',
            examiner,
            scope: examiner ? 'examiner' : 'case',
            total: ids.length,
            returned: ids.length,
            capped: false,
            cap: 100000,
          })
        },
      ),
      http.get('/api/v1/cases/:caseId/artifact_reviews/stats', () =>
        HttpResponse.json({
          examiners: [],
          case: { opened: 0, reviewed: 1 },
          population: {
            total: 10,
            name: 'artifacts_in_case',
            label: 'every artifact recorded in this case, of every type',
            includes_non_reviewable_rows: true,
            exact: true,
          },
          reviewed_is_subset_of_opened: true,
          counts_are_distinct_artifacts: true,
        }),
      ),
    )
    mockPost(() => ({ examiner: 'local', reviews_recorded: 1 }))

    const ledger = renderHook(() => useReviewLedger(CASE))
    const row = renderHook(() => useReviewEntry(CASE, A))

    // A write completes while the read for "alice" is still out: the server's
    // name is learned and the right list is read under it.
    await act(async () => {
      await reviewLedgerWriter(CASE).markReviewed(B)
    })
    await waitFor(() => expect(ledger.result.current.examiner).toBe('local'))
    await waitFor(() => expect(row.result.current.reviewedByMe).toBe(true))

    // Now the slow read for "alice" lands. It must not file alice's (empty)
    // list under the name "local" — that would turn A into "not known" or
    // "not mine", and the guard in learnExaminer would then never re-read it.
    aliceRead.open()
    await waitFor(() => expect(ledger.result.current.loaded).toBe(true))
    expect(row.result.current.reviewedByMe).toBe(true)
  })

  it('does not stand down a review queued while the opening batch was in flight', async () => {
    mockLedger()
    const openedPost = gate()
    const reviewedPost = gate()
    server.use(
      http.post(
        '/api/v1/cases/:caseId/artifact_reviews',
        async ({ request }) => {
          const body = (await request.json()) as SentBatch
          posted.push(body)
          const state = body.marks[0]?.state
          if (state === 'opened') await openedPost.wait
          if (state === 'reviewed') await reviewedPost.wait
          return HttpResponse.json({
            examiner: 'local',
            received: body.marks.length,
            openings_recorded: state === 'opened' ? body.marks.length : 0,
            reviews_recorded: state === 'reviewed' ? body.marks.length : 0,
            reviews_withdrawn: 0,
            unchanged: 0,
            rejected: [],
            rejected_reason: 'artifact_not_in_case',
            batch_max: 1000,
          })
        },
      ),
    )
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loaded).toBe(true))
    const row = renderHook(() => useReviewEntry(CASE, A))

    // The opening goes out and is held in flight...
    const writer = reviewLedgerWriter(CASE)
    act(() => writer.markOpened(A))
    const flushing = act(() => writer.flushOpenings())
    await waitFor(() =>
      expect(posted.some((b) => b.marks[0]?.state === 'opened')).toBe(true),
    )

    // ...and while it is out, the examiner marks the same row reviewed.
    let reviewing: Promise<void> = Promise.resolve()
    try {
      act(() => {
        reviewing = writer.markReviewed(A)
      })
      await waitFor(() => expect(row.result.current.pending).toBe('reviewed'))

      // The opening's response lands first. The row is still waiting on its
      // review, and must go on saying so: clearing it here re-enabled the
      // button with the review's POST still in flight.
      openedPost.open()
      await flushing
      await waitFor(() =>
        expect(row.result.current.opened).toBe(true),
      )
      expect(row.result.current.pending).toBe('reviewed')
    } finally {
      // Never leave a request held open into the next test.
      openedPost.open()
      reviewedPost.open()
    }

    await act(async () => {
      await reviewing
    })
    expect(row.result.current.pending).toBeNull()
    expect(row.result.current.reviewedByMe).toBe(true)
  })
})

/**
 * The ledger as a five-hundred-row table has to use it.
 *
 * `useReviewLedger` hands back the whole roll-up, so every component holding it
 * re-renders whenever anything anywhere in the ledger changes. That is right
 * for the panel, which counts the whole case; it is badly wrong for a row,
 * which is asking one question about one id. These two entry points exist so a
 * table can spend one row's work on one row's mark, and moving the ledger onto
 * the server did not change that arithmetic.
 */
describe('useReviewEntry and useReviewLedgerWriter at table scale', () => {
  it('re-renders a row only when that row’s own mark changes', async () => {
    // The examiner is known before the click. Learning it for the first time
    // legitimately changes every row — "is this review yours" goes from not
    // known to no — and that is a once-per-session event, not the per-click
    // cost this case is holding.
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({})
    mockPost(() => ({ examiner: 'bob', reviews_recorded: 1 }))
    let watchedRenders = 0
    let otherRenders = 0
    const watched = renderHook(() => {
      watchedRenders++
      return useReviewEntry(CASE, A)
    })
    const other = renderHook(() => {
      otherRenders++
      return useReviewEntry(CASE, B)
    })
    await waitFor(() => expect(other.result.current.reviewed).toBe(false))

    const before = otherRenders
    const watchedBefore = watchedRenders
    await act(async () => {
      await reviewLedgerWriter(CASE).markReviewed(A)
    })

    // The row that was marked reads its new mark…
    expect(watched.result.current.reviewed).toBe(true)
    expect(watchedRenders).toBeGreaterThan(watchedBefore)
    // …and the row that was not is not touched at all. This is the whole
    // point: one click must not cost the table five hundred renders.
    expect(otherRenders).toBe(before)
    expect(other.result.current.reviewed).toBe(false)
  })

  it('gives a writer that never re-renders when the ledger changes', async () => {
    mockLedger({})
    mockPost(() => ({ reviews_recorded: 1 }))
    let writerRenders = 0
    const writer = renderHook(() => {
      writerRenders++
      return useReviewLedgerWriter(CASE)
    })
    const before = writerRenders

    await act(async () => {
      await writer.result.current.markReviewed(A)
    })
    act(() => writer.result.current.markOpened(B))
    await act(async () => {
      await writer.result.current.flushOpenings()
    })

    // A cell that only ever records an opening reads nothing, so it has no
    // business being woken when somebody else's row is marked — and it must not
    // hold a subscription that would make it so.
    expect(writerRenders).toBe(before)
  })

  it('gives one stable writer per case, so an effect is not rebuilt each render', () => {
    expect(reviewLedgerWriter(CASE)).toBe(reviewLedgerWriter(CASE))
    expect(reviewLedgerWriter(CASE)).not.toBe(reviewLedgerWriter(OTHER_CASE))
  })

  it('does not re-render rows a whole-store recompute left unchanged', async () => {
    // A stale session record, which is ordinary: this browser guesses "bob"
    // from what it has, and the server answers that it is actually filing marks
    // under "local". That forces a re-read of "which of these reviews are
    // mine", and the answer for every row it republishes is the one already on
    // screen.
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({ opened: [A], reviewed: [A], mine: [] })
    mockPost(() => ({ examiner: 'local', reviews_recorded: 1 }))

    let renders = 0
    const untouched = renderHook(() => {
      renders++
      return useReviewEntry(CASE, B)
    })
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() =>
      expect(untouched.result.current.reviewedByMe).toBe(false),
    )
    const settled = renders

    await act(async () => {
      await reviewLedgerWriter(CASE).markReviewed(A)
    })
    await waitFor(() => expect(ledger.result.current.examiner).toBe('local'))
    await new Promise((resolve) => setTimeout(resolve, 400))

    // Every row was recomputed and row B's answer did not move, so row B keeps
    // its entry object and React never re-renders it. Without that, learning
    // the examiner's real name repaints the whole five-hundred-row table.
    expect(untouched.result.current.reviewedByMe).toBe(false)
    expect(renders).toBe(settled)
  })

  it('reports the same marks to a row and to the roll-up', async () => {
    mockLedger({ opened: [A], reviewed: [A], caseOpened: 1, caseReviewed: 1 })
    const ledger = renderHook(() => useReviewLedger(CASE))
    const row = renderHook(() => useReviewEntry(CASE, A))

    await waitFor(() => expect(ledger.result.current.loaded).toBe(true))
    // Two ways of reading one ledger must never disagree: a row that displays
    // as reviewed when the roll-up does not count it — or the reverse — is
    // exactly the false record the ledger exists to prevent.
    expect(row.result.current.reviewed).toBe(true)
    expect(ledger.result.current.counts.reviewed).toBe(1)
  })
})

/**
 * A read that failed stays failed until somebody asks again — and the asking is
 * the examiner's, not a timer's.
 *
 * An automatic retry loop would be worse than no retry at all: a read that
 * succeeded unseen, minutes after the panel had already said the ledger could
 * not be read, leaves the screen asserting two different things with no event
 * the examiner can point to as the moment it changed. So the recovery is an act
 * — and because it is an act, its outcome has to be reported as one. A second
 * failure that quietly restored the same sentence would be indistinguishable
 * from a button that does nothing.
 */
describe('a failed read is retried when the examiner asks, and only then', () => {
  /** The whole family answering 500, counting how many times it was asked. */
  function mockUnreadableLedger(): { reads: number } {
    const counter = { reads: 0 }
    const fail = () => {
      counter.reads++
      return HttpResponse.json(
        { error: { code: 'JOB_FAILED', message: 'the ledger is unavailable' } },
        { status: 500 },
      )
    }
    server.use(
      http.get('/api/v1/cases/:caseId/artifact_reviews/ids', fail),
      http.get('/api/v1/cases/:caseId/artifact_reviews/stats', fail),
    )
    return counter
  }

  it('does not read again by itself, however many rows ask', async () => {
    const counter = mockUnreadableLedger()
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loadError).toBeTruthy())
    const settled = counter.reads

    // More readers mounting is not an event that re-reads the case. If it
    // were, a table scrolling new rows into view would retry on its own.
    renderHook(() => useReviewEntry(CASE, A))
    renderHook(() => useReviewEntry(CASE, B))
    await new Promise((resolve) => setTimeout(resolve, 60))
    expect(counter.reads).toBe(settled)
    expect(ledger.result.current.retrying).toBe(false)
    expect(ledger.result.current.retriesFailed).toBe(0)
  })

  it('reads the case again when the examiner asks, and says what it found', async () => {
    mockUnreadableLedger()
    const ledger = renderHook(() => useReviewLedger(CASE))
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(ledger.result.current.loadError).toBeTruthy())
    expect(row.result.current.reviewed).toBeNull()

    server.resetHandlers()
    mockLedger({
      opened: [A],
      reviewed: [A],
      examiners: [
        {
          examiner: 'alice',
          opened: 1,
          reviewed: 1,
          first_opened_at: 1_690_000_000,
          last_activity_at: 1_690_100_000,
        },
      ],
    })
    await act(async () => {
      await ledger.result.current.retryLoad()
    })

    expect(ledger.result.current.loadError).toBeNull()
    expect(ledger.result.current.counts).toEqual({ opened: 1, reviewed: 1 })
    expect(ledger.result.current.examiners[0].examiner).toBe('alice')
    expect(ledger.result.current.retriedAt).toBeGreaterThan(0)
    expect(ledger.result.current.retryFailedAt).toBeNull()
    // The row that could not be read now can be, and it says so.
    expect(row.result.current.reviewed).toBe(true)
  })

  it('says a retry that failed again failed, rather than repeating itself', async () => {
    mockUnreadableLedger()
    const ledger = renderHook(() => useReviewLedger(CASE))
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(ledger.result.current.loadError).toBeTruthy())

    await act(async () => {
      await ledger.result.current.retryLoad()
    })
    expect(ledger.result.current.retriesFailed).toBe(1)
    expect(ledger.result.current.retryFailedAt).toBeGreaterThan(0)

    await act(async () => {
      await ledger.result.current.retryLoad()
    })
    // A second failure is a second event. Counting them is what keeps the
    // screen from answering an act with the sentence it was already showing.
    expect(ledger.result.current.retriesFailed).toBe(2)
    expect(ledger.result.current.loadError).toBeTruthy()
    // And a retry never manufactures an answer: the rows it could not read are
    // still not known, never unopened.
    expect(row.result.current.opened).toBeNull()
    expect(row.result.current.reviewed).toBeNull()
    expect(ledger.result.current.counts).toEqual({
      opened: null,
      reviewed: null,
    })
  })

  it('reports the re-read as in flight while it runs, and not as an answer', async () => {
    mockUnreadableLedger()
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loadError).toBeTruthy())

    let release: (() => void) | null = null
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    server.resetHandlers()
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
          cap: 100000,
        })
      }),
      http.get('/api/v1/cases/:caseId/artifact_reviews/stats', async () => {
        await held
        return HttpResponse.json({
          examiners: [],
          case: { opened: 0, reviewed: 0 },
          population: {
            total: 10,
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

    let settled: Promise<void>
    act(() => {
      settled = ledger.result.current.retryLoad()
    })
    await waitFor(() => expect(ledger.result.current.retrying).toBe(true))
    // In flight is not an answer: the counts are still the ones that could not
    // be read, and they are still null rather than zero.
    expect(ledger.result.current.counts).toEqual({
      opened: null,
      reviewed: null,
    })

    await act(async () => {
      release!()
      await settled!
    })
    expect(ledger.result.current.retrying).toBe(false)
    expect(ledger.result.current.counts).toEqual({ opened: 0, reviewed: 0 })
  })

  it('does not start a second read on top of one already running', async () => {
    const counter = mockUnreadableLedger()
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loadError).toBeTruthy())
    const settled = counter.reads

    await act(async () => {
      await Promise.all([
        ledger.result.current.retryLoad(),
        ledger.result.current.retryLoad(),
        ledger.result.current.retryLoad(),
      ])
    })

    // Three impatient presses are one re-read, and one failure, not three: a
    // re-read costs exactly what the first read cost, once.
    expect(counter.reads).toBe(settled * 2)
    expect(ledger.result.current.retriesFailed).toBe(1)
  })
})

/**
 * Which examiner holds the review on ONE row.
 *
 * The per-examiner panel answers who has worked the case; it cannot answer who
 * reviewed this record, and with two colleagues on a case those are different
 * questions. The answer needs the row's own history, so it is read when an
 * examiner asks about that row and never for a table full of rows nobody asked
 * about — and until it lands, the row says it does not know rather than naming
 * anybody.
 */
describe('who reviewed this row is read only when somebody asks', () => {
  const HISTORY = '/api/v1/cases/:caseId/artifact_reviews/history'

  function mockHistory(
    events: { artifact_id: string; examiner: string; action: string }[],
    options: { capped?: boolean; hold?: Promise<void> } = {},
  ): { reads: number } {
    const counter = { reads: 0 }
    server.use(
      http.get(HISTORY, async ({ request }) => {
        counter.reads++
        if (options.hold) await options.hold
        const wanted = new URL(request.url).searchParams.get('artifact_id')
        const mine = events.filter((e) => e.artifact_id === wanted)
        return HttpResponse.json({
          events: mine.map((e, i) => ({ ...e, at: i + 1 })),
          artifact_id: wanted,
          examiner: null,
          returned: mine.length,
          limit: 1000,
          capped: options.capped === true,
        })
      }),
    )
    return counter
  }

  it('asks nothing for rows nobody asked about', async () => {
    mockLedger({ opened: [A, B], reviewed: [A, B] })
    const counter = mockHistory([])
    const first = renderHook(() => useReviewEntry(CASE, A))
    renderHook(() => useReviewEntry(CASE, B))
    await waitFor(() => expect(first.result.current.reviewed).toBe(true))

    // Cheap per row is not free at five hundred rows. Nothing is spent until
    // an examiner asks about a particular one.
    expect(counter.reads).toBe(0)
    expect(first.result.current.attribution.state).toBe('not-asked')
    expect(first.result.current.attribution.examiners).toEqual([])
  })

  it('names the examiner who holds the review, once asked', async () => {
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({ opened: [A], reviewed: [A], mine: [] })
    const counter = mockHistory([
      { artifact_id: A, examiner: 'alice', action: 'opened' },
      { artifact_id: A, examiner: 'alice', action: 'reviewed' },
    ])
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewed).toBe(true))

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('read'),
    )
    expect(row.result.current.attribution.examiners).toEqual(['alice'])
    expect(counter.reads).toBe(1)
    // Asking who does not change what: the row still carries the review it
    // carried, and it is still not this examiner's.
    expect(row.result.current.reviewed).toBe(true)
    expect(row.result.current.reviewedByMe).toBe(false)
  })

  it('never names anybody while the answer is still being read', async () => {
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({ opened: [A], reviewed: [A], mine: [] })
    let release: (() => void) | null = null
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    mockHistory(
      [{ artifact_id: A, examiner: 'alice', action: 'reviewed' }],
      { hold: held },
    )
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewed).toBe(true))

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('reading'),
    )
    // A half-read attribution names nobody. "Nobody" and "somebody whose name
    // is still coming" are different claims, and only one of them is true.
    expect(row.result.current.attribution.examiners).toEqual([])

    await act(async () => {
      release!()
      await waitFor(() =>
        expect(row.result.current.attribution.state).toBe('read'),
      )
    })
    expect(row.result.current.attribution.examiners).toEqual(['alice'])
  })

  it('says the name could not be read rather than guessing at one', async () => {
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({ opened: [A], reviewed: [A], mine: [] })
    server.use(
      http.get(HISTORY, () =>
        HttpResponse.json(
          { error: { code: 'JOB_FAILED', message: 'history unavailable' } },
          { status: 500 },
        ),
      ),
    )
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewed).toBe(true))

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('unavailable'),
    )
    expect(row.result.current.attribution.examiners).toEqual([])
    // The review itself is unaffected: not knowing who made it is not evidence
    // that nobody did.
    expect(row.result.current.reviewed).toBe(true)
  })

  it('treats a history that stopped at its ceiling as no answer at all', async () => {
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({ opened: [A], reviewed: [A], mine: [] })
    mockHistory([{ artifact_id: A, examiner: 'alice', action: 'reviewed' }], {
      capped: true,
    })
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewed).toBe(true))

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('unavailable'),
    )
    // A partial reading of an append-only log can name a reviewer whose
    // withdrawal was on the page that did not arrive.
    expect(row.result.current.attribution.examiners).toEqual([])
  })

  it('spends one request however many times a row is asked about at once', async () => {
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({ opened: [A], reviewed: [A], mine: [] })
    const counter = mockHistory([
      { artifact_id: A, examiner: 'alice', action: 'reviewed' },
    ])
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewed).toBe(true))

    const writer = reviewLedgerWriter(CASE)
    act(() => {
      writer.askWhoReviewed(A)
      writer.askWhoReviewed(A)
      writer.askWhoReviewed(A)
    })
    // Impatience is not three questions. A reading already in flight IS the
    // answer to the ask, exactly as a re-read already running is the answer to
    // the panel's retry.
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('read'),
    )
    expect(counter.reads).toBe(1)
  })

  it('keeps one row’s reviewer off another row', async () => {
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({ opened: [A, B], reviewed: [A, B], mine: [] })
    mockHistory([
      { artifact_id: A, examiner: 'alice', action: 'reviewed' },
      { artifact_id: B, examiner: 'carol', action: 'reviewed' },
    ])
    const first = renderHook(() => useReviewEntry(CASE, A))
    const second = renderHook(() => useReviewEntry(CASE, B))
    await waitFor(() => expect(second.result.current.reviewed).toBe(true))

    const writer = reviewLedgerWriter(CASE)
    act(() => {
      writer.askWhoReviewed(A)
      writer.askWhoReviewed(B)
    })
    await waitFor(() =>
      expect(second.result.current.attribution.state).toBe('read'),
    )
    // A name on the wrong row is a false attribution, which is the one thing
    // worse than no attribution.
    expect(first.result.current.attribution.examiners).toEqual(['alice'])
    expect(second.result.current.attribution.examiners).toEqual(['carol'])
  })

  it('says so when the history shows the review the row displayed has gone', async () => {
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({ opened: [A], reviewed: [A], mine: [] })
    mockHistory([
      { artifact_id: A, examiner: 'alice', action: 'reviewed' },
      { artifact_id: A, examiner: 'alice', action: 'review_withdrawn' },
    ])
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewed).toBe(true))

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() => expect(row.result.current.reviewed).toBe(false))

    // The history is the exact record and the listing was read minutes ago, so
    // the row stops claiming a review. But it stopped because of something the
    // examiner did, and a row that quietly drops a claim between one glance and
    // the next is the two-answers-no-event failure in miniature.
    expect(row.result.current.error).toMatch(/withdrawn/i)
    expect(row.result.current.attribution.state).toBe('read')
    expect(row.result.current.attribution.examiners).toEqual([])
  })

  it('does not leave a withdrawn reviewer’s name standing on the row', async () => {
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({ opened: [A], reviewed: [A], mine: [A] })
    mockHistory([
      { artifact_id: A, examiner: 'alice', action: 'reviewed' },
      { artifact_id: A, examiner: 'bob', action: 'reviewed' },
    ])
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewedByMe).toBe(true))

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('read'),
    )

    mockPost(() => ({ examiner: 'bob', reviews_withdrawn: 1 }))
    await act(async () => {
      await reviewLedgerWriter(CASE).unmarkReviewed(A)
    })

    // The row changed underneath the answer, so the answer is discarded rather
    // than left on screen describing a state that no longer holds.
    expect(row.result.current.attribution.state).not.toBe('read')
    expect(row.result.current.attribution.examiners).toEqual([])
  })
})

/**
 * A name on screen is an attribution, and an attribution carries a date.
 *
 * The reading that names a colleague is taken at a moment and is true of that
 * moment. It is never refreshed on a timer — a name that changed with no event
 * the examiner could point at is the same failure the panel's re-read button
 * exists to prevent — so instead the row carries the time the reading was
 * taken, and the examiner can take another whenever they want one.
 */
describe('a name the row shows says which reading it came from', () => {
  const HISTORY = '/api/v1/cases/:caseId/artifact_reviews/history'

  /** History whose events a test can change between one reading and the next. */
  function mockMutableHistory(state: {
    events: { examiner: string; action: string }[]
    fail?: boolean
  }): { reads: number } {
    const counter = { reads: 0 }
    server.use(
      http.get(HISTORY, ({ request }) => {
        counter.reads++
        if (state.fail) {
          return HttpResponse.json(
            { error: { code: 'JOB_FAILED', message: 'history unavailable' } },
            { status: 500 },
          )
        }
        const wanted = new URL(request.url).searchParams.get('artifact_id')
        return HttpResponse.json({
          events: state.events.map((e, i) => ({
            ...e,
            artifact_id: wanted,
            at: i + 1,
          })),
          artifact_id: wanted,
          examiner: null,
          returned: state.events.length,
          limit: 1000,
          capped: false,
        })
      }),
    )
    return counter
  }

  async function readRow() {
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
    mockLedger({ opened: [A], reviewed: [A], mine: [] })
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(row.result.current.reviewed).toBe(true))
    return row
  }

  it('stamps the reading with the moment it was taken', async () => {
    const state = { events: [{ examiner: 'alice', action: 'reviewed' }] }
    mockMutableHistory(state)
    const row = await readRow()
    const before = Math.floor(Date.now() / 1000)

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('read'),
    )

    const { readAt, failedAt, examiners } = row.result.current.attribution
    expect(examiners).toEqual(['alice'])
    // Not "now": the moment the answer was read. A name with no date cannot be
    // told apart from a name read an hour ago.
    expect(readAt).not.toBeNull()
    expect(readAt!).toBeGreaterThanOrEqual(before)
    expect(failedAt).toBeNull()
  })

  it('never stamps a reading that did not complete', async () => {
    const state = { events: [], fail: true }
    mockMutableHistory(state)
    const row = await readRow()

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('unavailable'),
    )
    // A stamp is a claim that a reading was taken. There was none.
    expect(row.result.current.attribution.readAt).toBeNull()
    expect(row.result.current.attribution.examiners).toEqual([])
    expect(row.result.current.attribution.failedAt).not.toBeNull()
  })

  it('reads again when the examiner asks again, and re-stamps', async () => {
    const state = { events: [{ examiner: 'alice', action: 'reviewed' }] }
    const counter = mockMutableHistory(state)
    const row = await readRow()

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.examiners).toEqual(['alice']),
    )
    const first = row.result.current.attribution.readAt

    // The colleague withdraws. Nothing on this screen may learn that on its
    // own — but the examiner may ask, and asking is an act with a time.
    state.events = [
      { examiner: 'alice', action: 'reviewed' },
      { examiner: 'alice', action: 'review_withdrawn' },
      { examiner: 'carol', action: 'reviewed' },
    ]
    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.examiners).toEqual(['carol']),
    )

    expect(counter.reads).toBe(2)
    expect(row.result.current.attribution.readAt).not.toBeNull()
    expect(row.result.current.attribution.readAt!).toBeGreaterThanOrEqual(
      first!,
    )
    // And the change is an event on the row, not a substitution nobody sees:
    // an examiner who quoted the earlier name must be able to account for it.
    expect(row.result.current.error).toMatch(/alice/)
    expect(row.result.current.error).toMatch(/carol/)
  })

  it('says nothing changed when a second reading agrees with the first', async () => {
    const state = { events: [{ examiner: 'alice', action: 'reviewed' }] }
    mockMutableHistory(state)
    const row = await readRow()

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('read'),
    )
    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('read'),
    )

    // A confirmation is not an incident. Crying change on a reading that said
    // the same thing teaches the examiner to ignore the one that does not.
    expect(row.result.current.error).toBeNull()
    expect(row.result.current.attribution.examiners).toEqual(['alice'])
  })

  it('keeps the name it read while it is reading again', async () => {
    const state = { events: [{ examiner: 'alice', action: 'reviewed' }] }
    mockMutableHistory(state)
    const row = await readRow()

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('read'),
    )
    const first = row.result.current.attribution.readAt

    let release: (() => void) | null = null
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    server.use(
      http.get(HISTORY, async ({ request }) => {
        await held
        const wanted = new URL(request.url).searchParams.get('artifact_id')
        return HttpResponse.json({
          events: [
            { artifact_id: wanted, examiner: 'carol', action: 'reviewed', at: 1 },
          ],
          artifact_id: wanted,
          examiner: null,
          returned: 1,
          limit: 1000,
          capped: false,
        })
      }),
    )

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('reading'),
    )
    // The earlier reading is still what this row knows, and it still says when
    // it was taken. Blanking it would leave the row unable to say anything at
    // all about a review it had already attributed.
    expect(row.result.current.attribution.examiners).toEqual(['alice'])
    expect(row.result.current.attribution.readAt).toBe(first)

    await act(async () => {
      release!()
      await waitFor(() =>
        expect(row.result.current.attribution.state).toBe('read'),
      )
    })
    expect(row.result.current.attribution.examiners).toEqual(['carol'])
  })

  it('does not drop a name it read because a re-reading failed', async () => {
    const state: { events: { examiner: string; action: string }[]; fail?: boolean } =
      { events: [{ examiner: 'alice', action: 'reviewed' }] }
    mockMutableHistory(state)
    const row = await readRow()

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('read'),
    )
    const first = row.result.current.attribution.readAt

    state.fail = true
    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('unavailable'),
    )

    // The failed re-reading is not evidence that the earlier one was wrong. It
    // keeps its names and its stamp, and the failure gets a time of its own.
    expect(row.result.current.attribution.examiners).toEqual(['alice'])
    expect(row.result.current.attribution.readAt).toBe(first)
    expect(row.result.current.attribution.failedAt).not.toBeNull()
  })

  it('dates the change notice rather than calling it “just now”', async () => {
    const state = { events: [{ examiner: 'alice', action: 'reviewed' }] }
    mockMutableHistory(state)
    const row = await readRow()

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.examiners).toEqual(['alice']),
    )

    state.events = [
      { examiner: 'alice', action: 'reviewed' },
      { examiner: 'alice', action: 'review_withdrawn' },
      { examiner: 'carol', action: 'reviewed' },
    ]
    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.examiners).toEqual(['carol']),
    )

    const message = row.result.current.error!
    // "just now" is a claim that decays: it is true for a second and quoted
    // for an hour. Every other forensic time on these screens is a stamp, and
    // so is each of the two readings this sentence sets against each other.
    expect(message).not.toMatch(/just now/i)
    expect(
      message.match(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/g),
    ).toHaveLength(2)
  })

  it('retires a change notice once a later reading replaces the one it describes', async () => {
    const state = { events: [{ examiner: 'alice', action: 'reviewed' }] }
    const counter = mockMutableHistory(state)
    const row = await readRow()

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.examiners).toEqual(['alice']),
    )

    state.events = [
      { examiner: 'alice', action: 'reviewed' },
      { examiner: 'alice', action: 'review_withdrawn' },
      { examiner: 'carol', action: 'reviewed' },
    ]
    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.examiners).toEqual(['carol']),
    )
    expect(row.result.current.error).toMatch(/alice/)

    // A third asking, minutes later, that agrees with the second. The notice
    // is a sentence about the reading the row was showing, and that reading
    // has just been replaced by a newer one — so the sentence goes with it.
    // Left standing it would present a reading taken minutes ago as the one
    // the row now carries, which is the recency a row may never assert.
    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() => expect(counter.reads).toBe(3))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('read'),
    )
    expect(row.result.current.error).toBeNull()
    expect(row.result.current.attribution.examiners).toEqual(['carol'])
  })

  it('dates the withdrawal notice, and retires it when the row is read again', async () => {
    const state = {
      events: [
        { examiner: 'alice', action: 'reviewed' },
        { examiner: 'alice', action: 'review_withdrawn' },
      ],
    }
    const counter = mockMutableHistory(state)
    const row = await readRow()

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() => expect(row.result.current.reviewed).toBe(false))
    const first = row.result.current.error!
    expect(first).toMatch(/withdrawn/i)
    expect(first).not.toMatch(/just now/i)
    expect(first).toMatch(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/)

    // The same discipline: the second reading is what the row now shows, so
    // the sentence about the first stops being on screen beside it.
    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() => expect(counter.reads).toBe(2))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('read'),
    )
    expect(row.result.current.error).toBeNull()
  })

  it('retires only its own notice, never a message about a write', async () => {
    const state = { events: [{ examiner: 'alice', action: 'reviewed' }] }
    mockMutableHistory(state)
    const row = await readRow()

    mockPost(() =>
      HttpResponse.json(
        { error: { code: 'JOB_FAILED', message: 'marks unavailable' } },
        { status: 500 },
      ),
    )
    await act(async () => {
      await reviewLedgerWriter(CASE).markReviewed(A)
    })
    expect(row.result.current.error).toMatch(/not recorded/i)

    act(() => reviewLedgerWriter(CASE).askWhoReviewed(A))
    await waitFor(() =>
      expect(row.result.current.attribution.state).toBe('read'),
    )

    // A reading retires the sentence the reading path itself wrote, and
    // nothing else. A review that was not recorded is still not recorded, and
    // an examiner who asked who holds this row has not been told otherwise.
    expect(row.result.current.error).toMatch(/not recorded/i)
  })
})

/**
 * A re-read the examiner asked for costs what it has to and no more.
 *
 * The ledger is four responses. Re-reading two hundred-thousand-id listings to
 * recover a roll-up that failed on its own is a cost the examiner pays for
 * nothing — and on a case at scale it is the difference between a re-read that
 * answers and one that times out too. What narrowing must not buy is a panel
 * that looks wholly fresh when only part of it is.
 */
describe('a re-read asks again only for what failed', () => {
  interface PartsFixture {
    openedFails?: boolean
    reviewedFails?: boolean
    mineFails?: boolean
    statsFails?: boolean
    opened?: string[]
    reviewed?: string[]
    mine?: string[]
  }

  /** Each of the four responses independently answerable, and counted. */
  function mockParts(fixture: PartsFixture) {
    const reads = { opened: 0, reviewed: 0, mine: 0, stats: 0 }
    const fail = (what: string) =>
      HttpResponse.json(
        { error: { code: 'JOB_FAILED', message: `${what} unavailable` } },
        { status: 500 },
      )
    server.use(
      http.get('/api/v1/cases/:caseId/artifact_reviews/ids', ({ request }) => {
        const params = new URL(request.url).searchParams
        const state = params.get('state')
        const examiner = params.get('examiner')
        const which = examiner
          ? 'mine'
          : state === 'opened'
            ? 'opened'
            : 'reviewed'
        reads[which]++
        const broken =
          which === 'opened'
            ? fixture.openedFails
            : which === 'reviewed'
              ? fixture.reviewedFails
              : fixture.mineFails
        if (broken) return fail(`the ${which} listing`)
        const ids =
          which === 'opened'
            ? (fixture.opened ?? [])
            : which === 'mine'
              ? (fixture.mine ?? [])
              : (fixture.reviewed ?? [])
        return HttpResponse.json({
          ids,
          state: state ?? 'reviewed',
          examiner,
          scope: examiner ? 'examiner' : 'case',
          total: ids.length,
          returned: ids.length,
          capped: false,
          cap: 100000,
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

  beforeEach(() => {
    localStorage.setItem('seance_session', JSON.stringify({ username: 'bob' }))
  })

  it('re-reads the roll-up alone when the roll-up alone failed', async () => {
    const fixture: PartsFixture = {
      opened: [A, B],
      reviewed: [A],
      mine: [],
      statsFails: true,
    }
    const reads = mockParts(fixture)
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loadError).toBeTruthy())
    expect(reads).toEqual({ opened: 1, reviewed: 1, mine: 1, stats: 1 })

    fixture.statsFails = false
    await act(async () => {
      await ledger.result.current.retryLoad()
    })

    // The two listings came back the first time and were not in question. On a
    // case at the listing ceiling they are two hundred thousand ids nobody
    // needed re-fetched to recover one small roll-up.
    expect(reads).toEqual({ opened: 1, reviewed: 1, mine: 1, stats: 2 })
    expect(ledger.result.current.loadError).toBeNull()
    expect(ledger.result.current.counts).toEqual({ opened: 2, reviewed: 1 })
    expect(ledger.result.current.retriedAt).toBeGreaterThan(0)
  })

  it('says which parts the re-read covered and which it did not', async () => {
    const fixture: PartsFixture = {
      opened: [A, B],
      reviewed: [A],
      mine: [],
      statsFails: true,
    }
    const reads = mockParts(fixture)
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loadError).toBeTruthy())
    void reads

    fixture.statsFails = false
    await act(async () => {
      await ledger.result.current.retryLoad()
    })

    const scope = ledger.result.current.retryScope
    expect(scope).not.toBeNull()
    expect(scope).toHaveLength(1)
    expect(scope![0]).toMatch(/roll-up/i)

    // Every part says when it was last read, so a panel cannot present a
    // mixture of one fresh figure and three older ones as one reading.
    const parts = ledger.result.current.parts
    expect(parts.map((p) => p.part).sort()).toEqual([
      'mine',
      'opened',
      'reviewed',
      'stats',
    ])
    const stats = parts.find((p) => p.part === 'stats')!
    const opened = parts.find((p) => p.part === 'opened')!
    expect(stats.readAt).not.toBeNull()
    expect(opened.readAt).not.toBeNull()
    expect(stats.readAt!).toBeGreaterThanOrEqual(opened.readAt!)
    expect(parts.every((p) => p.error == null)).toBe(true)
  })

  it('keeps the row answers the narrowed re-read did not touch', async () => {
    const fixture: PartsFixture = {
      opened: [A],
      reviewed: [A],
      mine: [],
      statsFails: true,
    }
    mockParts(fixture)
    const row = renderHook(() => useReviewEntry(CASE, A))
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(row.result.current.reviewed).toBe(true))

    fixture.statsFails = false
    await act(async () => {
      await ledger.result.current.retryLoad()
    })

    // The listings were not re-read, so what they said still stands — and a
    // row is never quietly demoted to "not known" by a retry that did not ask
    // about it.
    expect(row.result.current.opened).toBe(true)
    expect(row.result.current.reviewed).toBe(true)
    expect(row.result.current.reviewedByMe).toBe(false)
  })

  it('reports a part that failed without claiming the whole is unread', async () => {
    const fixture: PartsFixture = {
      opened: [A],
      reviewed: [A],
      mine: [],
      openedFails: true,
    }
    mockParts(fixture)
    const ledger = renderHook(() => useReviewLedger(CASE))
    const row = renderHook(() => useReviewEntry(CASE, A))
    await waitFor(() => expect(ledger.result.current.loadError).toBeTruthy())

    // The roll-up came back, so the counts are real and are stated.
    expect(ledger.result.current.counts).toEqual({ opened: 1, reviewed: 1 })
    // The opened listing did not, so no row may be called unopened.
    expect(row.result.current.opened).toBeNull()
    expect(row.result.current.reviewed).toBe(true)
    expect(ledger.result.current.loadError).toMatch(
      /not a record of what has been examined/i,
    )
    const opened = ledger.result.current.parts.find((p) => p.part === 'opened')!
    expect(opened.error).toBeTruthy()
    expect(opened.failedAt).not.toBeNull()
    expect(opened.readAt).toBeNull()
  })

  it('re-reads everything when everything failed', async () => {
    const fixture: PartsFixture = {
      openedFails: true,
      reviewedFails: true,
      mineFails: true,
      statsFails: true,
    }
    const reads = mockParts(fixture)
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loadError).toBeTruthy())

    await act(async () => {
      await ledger.result.current.retryLoad()
    })

    expect(reads).toEqual({ opened: 2, reviewed: 2, mine: 2, stats: 2 })
    expect(ledger.result.current.retryScope).toHaveLength(4)
    expect(ledger.result.current.retriesFailed).toBe(1)
    expect(ledger.result.current.retryFailedAt).toBeGreaterThan(0)
  })

  it('says a narrowed re-read that failed again failed', async () => {
    const fixture: PartsFixture = {
      opened: [A],
      reviewed: [A],
      mine: [],
      statsFails: true,
    }
    const reads = mockParts(fixture)
    const ledger = renderHook(() => useReviewLedger(CASE))
    await waitFor(() => expect(ledger.result.current.loadError).toBeTruthy())

    await act(async () => {
      await ledger.result.current.retryLoad()
    })

    expect(reads.stats).toBe(2)
    expect(reads.opened).toBe(1)
    expect(ledger.result.current.retriesFailed).toBe(1)
    expect(ledger.result.current.retryFailedAt).toBeGreaterThan(0)
    expect(ledger.result.current.retryScope).toHaveLength(1)
    // Narrowing does not make a failure quieter: the part that is still unread
    // is still named, and the attempt still has a time of its own.
    const stats = ledger.result.current.parts.find((p) => p.part === 'stats')!
    expect(stats.error).toBeTruthy()
    expect(stats.readAt).toBeNull()
  })
})
