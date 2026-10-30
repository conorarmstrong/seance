import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { server } from '../../test/server'
import { PivotCtx } from '../../app/PivotContext'
import { FindingsPage } from './FindingsPage'

const CASE_ID = 'case-1'

function mock(body: unknown) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/findings`, () =>
      HttpResponse.json(body as Parameters<typeof HttpResponse.json>[0]),
    ),
  )
}

function finding(over: Record<string, unknown> = {}) {
  return {
    finding_kind: 'timestomp',
    name: 'Timestamps reordered on svchost.exe',
    confidence: 'notable',
    confidence_rank: 1,
    observation:
      'The $STANDARD_INFORMATION and $FILE_NAME timestamps of svchost.exe are inconsistent.',
    evidence: [
      { name: 'si_modified', value: '2019-03-02T11:14:08Z' },
      { name: 'imphash', value: 'a9f3b1c0e2d4567890abcdef12345678' },
    ],
    inference: 'Rewriting $SI timestamps is how the time of an action is hidden.',
    qualification: 'It is also what a restore from backup looks like.',
    device_offset: 4096,
    source_module: 'plugin.findings.timestomp',
    subject_artifact_id: 'subj-1',
    grade: 'investigative_lead',
    grade_note: 'An investigative lead raised by Séance.',
    persisted: true,
    artifact_id: 'fnd-1',
    ...over,
  }
}

function body(over: Record<string, unknown> = {}) {
  const findings = (over.findings as unknown[]) ?? [finding()]
  return {
    findings,
    listed: findings.length,
    total: findings.length,
    truncated: false,
    by_confidence: { notable: findings.length },
    by_kind: { timestomp: findings.length },
    cross_view: {
      ran: true,
      declined: null,
      findings: 0,
      file_entries_compared_against: 412300,
      limits: [],
      complete: true,
    },
    detections: [
      {
        kind: 'timestomp',
        module: 'plugin.findings.timestomp',
        looks_for: 'NTFS $SI timestamps inconsistent with $FN.',
      },
    ],
    grade: 'investigative_lead',
    grade_note:
      'Every row here is an investigative lead raised by Séance, not a transcription of the evidence.',
    absence_note: '1 finding(s) from the 1 detection(s) this build carries.',
    ...over,
  }
}

function renderPage(openPivot = vi.fn()) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <PivotCtx.Provider value={{ openPivot }}>
        <MemoryRouter initialEntries={[`/cases/${CASE_ID}/findings`]}>
          <Routes>
            <Route path="/cases/:caseId/findings" element={<FindingsPage />} />
            <Route
              path="/cases/:caseId/artifacts/:artifactId"
              element={<div>artifact page</div>}
            />
          </Routes>
        </MemoryRouter>
      </PivotCtx.Provider>
    </QueryClientProvider>,
  )
  return openPivot
}

describe('FindingsPage (§2.2)', () => {
  /**
   * The obligation this screen carries that no other screen does. Every row is
   * Séance's own claim about the evidence, and Part VI forbids presenting that
   * as though it were a transcription. So the observation, the inference and
   * the qualification are three separate, labelled things — and the
   * qualification is never hidden.
   */
  it('renders the observation, the inference and the qualification as three labelled things', async () => {
    mock(body())
    renderPage()

    const card = await screen.findByTestId('fnd-card')
    // The observation, unlabelled body text: the checkable half.
    expect(
      within(card).getByText(/timestamps of svchost\.exe are inconsistent/),
    ).toBeInTheDocument()

    // The inference, labelled as a reading rather than a fact.
    const inference = within(card).getByTestId('fnd-inference')
    expect(inference).toHaveTextContent(/Séance's reading, not a fact/)
    expect(inference).toHaveTextContent(/is how the time of an action is hidden/)

    // The qualification, visible without any interaction. A reader who sees
    // only the claim has read half the finding.
    const qualification = within(card).getByTestId('fnd-qualification')
    expect(qualification).toBeVisible()
    expect(qualification).toHaveTextContent(/What it does not establish/)
    expect(qualification).toHaveTextContent(/restore from backup/)

    // And the grade is stated once, before the first row.
    expect(screen.getByTestId('fnd-grade')).toHaveTextContent(
      /investigative lead raised by Séance/,
    )
  })

  /** A finding with no inference shows none, rather than an empty heading. */
  it('shows no inference block when the observation speaks for itself', async () => {
    mock(body({ findings: [finding({ inference: null })] }))
    renderPage()
    await screen.findByTestId('fnd-card')
    expect(screen.queryByTestId('fnd-inference')).not.toBeInTheDocument()
    // The qualification is still there: it is not optional.
    expect(screen.getByTestId('fnd-qualification')).toBeVisible()
  })

  it('ranks strongest first and filters by confidence without lying about the totals', async () => {
    mock(
      body({
        findings: [
          finding({
            name: 'Signature does not match the bytes of a.exe',
            finding_kind: 'pe_signature_mismatch',
            confidence: 'strong',
            confidence_rank: 0,
            artifact_id: 'fnd-strong',
          }),
          finding({ name: 'A notable one', artifact_id: 'fnd-notable' }),
          finding({
            name: 'A weak one',
            confidence: 'weak',
            confidence_rank: 2,
            artifact_id: 'fnd-weak',
          }),
        ],
        by_confidence: { strong: 1, notable: 1, weak: 1 },
      }),
    )
    renderPage()

    const cards = await screen.findAllByTestId('fnd-card')
    expect(cards).toHaveLength(3)
    expect(cards[0]).toHaveTextContent('Signature does not match')
    expect(cards[2]).toHaveTextContent('A weak one')

    // Narrowing to one grade leaves the case-wide counts on the chips, so the
    // screen never reads as "this case has one finding".
    await userEvent.click(screen.getByRole('button', { name: /^Strong 1$/ }))
    expect(screen.getAllByTestId('fnd-card')).toHaveLength(1)
    expect(screen.getByRole('button', { name: /^All 3$/ })).toBeInTheDocument()
  })

  /** A grade with no findings is not offered at all, so a click can never
   *  produce an empty list with case-wide counts above it. */
  it('does not offer a grade this case has none of', async () => {
    mock(body({ by_confidence: { notable: 1, strong: 0, weak: 0 } }))
    renderPage()
    await screen.findByTestId('fnd-card')
    expect(screen.getByRole('button', { name: /^Weak 0$/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: /^Strong 0$/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: /^Notable 1$/ })).toBeEnabled()
  })

  /**
   * The chips are driven by the server's counts. A chip claiming rows that the
   * list does not contain means the two disagree, and blaming the filter would
   * be a fabricated explanation for it.
   */
  it('reports a disagreement between the counts and the list rather than explaining it away', async () => {
    mock(
      body({
        // The server says three weak leads and returns none of them.
        by_confidence: { notable: 1, weak: 3 },
        total: 4,
      }),
    )
    renderPage()
    await screen.findByTestId('fnd-card')
    await userEvent.click(screen.getByRole('button', { name: /^Weak 3$/ }))

    const note = screen.getByTestId('fnd-none-returned')
    expect(note).toHaveTextContent(/reports 3 weak leads and none came back/)
    expect(note).toHaveTextContent(/is not a finding that they do not exist/)
    expect(screen.queryAllByTestId('fnd-card')).toHaveLength(0)
  })

  /**
   * "No findings" means either "nothing matched the detections this build has"
   * or "nothing here looks for what you are after", and while this layer is
   * being built out the second is usually the truth.
   */
  it('an empty list carries the server sentence and what this build looks for', async () => {
    mock(
      body({
        findings: [],
        total: 0,
        listed: 0,
        by_confidence: {},
        by_kind: {},
        absence_note:
          'No findings. This build carries 1 detection(s), listed above: an empty list means nothing in this case matched THOSE.',
      }),
    )
    renderPage()

    const empty = await screen.findByTestId('fnd-empty')
    expect(empty).toHaveTextContent(/nothing in this case matched THOSE/)

    // And the detections themselves are on the screen, not only named.
    await userEvent.click(
      screen.getByRole('button', { name: /this build looks for/ }),
    )
    const list = screen.getByTestId('fnd-detections')
    expect(within(list).getByText('timestomp')).toBeInTheDocument()
    expect(
      within(list).getByText(/NTFS \$SI timestamps inconsistent/),
    ).toBeInTheDocument()
  })

  /**
   * "The whole-case checks ran and found nothing" and "they could not be run"
   * are different facts about the case, and showing the first when the second
   * is true tells the examiner the machine is clean on a question nobody asked.
   */
  it('says when the whole-case checks were not run', async () => {
    mock(
      body({
        cross_view: {
          ran: false,
          declined:
            'No file entries were recovered in this case, so the cross-view detections were not run.',
          findings: 0,
          file_entries_compared_against: 0,
          limits: [],
          complete: false,
        },
      }),
    )
    renderPage()
    const note = await screen.findByTestId('fnd-cross-view')
    expect(note).toHaveTextContent(/were\s+not run/)
    expect(note).toHaveTextContent(/No file entries were recovered/)
  })

  it('says when the whole-case checks ran but were capped', async () => {
    mock(
      body({
        cross_view: {
          ran: true,
          declined: null,
          findings: 2,
          file_entries_compared_against: 412300,
          limits: ['This case holds 900000 USN journal entries and the first 100000 were examined.'],
          complete: false,
        },
      }),
    )
    renderPage()
    const note = await screen.findByTestId('fnd-cross-view')
    expect(note).toHaveTextContent(/not over everything/)
    expect(note).toHaveTextContent(/the first 100000 were examined/)
    expect(note).toHaveTextContent(/is not a finding/)
  })

  /**
   * A cross-view row is computed when the list is requested, so it is not in
   * the database, the search index or the timeline. A reader citing it has
   * nothing to cite, and the row says so where it is read.
   */
  it('marks a computed row and offers no finding record for it', async () => {
    mock(
      body({
        findings: [
          finding({
            finding_kind: 'execution_of_absent_binary',
            name: 'DROPPER.EXE ran, and no file entry for it was recovered',
            persisted: false,
            artifact_id: undefined,
            not_persisted_note:
              'Computed from two views of the case when this list was requested, so it has no artifact of its own.',
          }),
        ],
      }),
    )
    renderPage()
    const card = await screen.findByTestId('fnd-card')
    expect(within(card).getByTestId('fnd-not-persisted')).toHaveTextContent(
      /no artifact of its own/,
    )
    // The subject is still openable — that is the point of it.
    expect(
      within(card).getByRole('link', { name: /Open the artifact this is about/ }),
    ).toHaveAttribute('href', `/cases/${CASE_ID}/artifacts/subj-1`)
    expect(
      within(card).queryByRole('link', { name: /Open the finding record/ }),
    ).not.toBeInTheDocument()
  })

  it('a persisted row opens both the subject and the finding record', async () => {
    mock(body())
    renderPage()
    const card = await screen.findByTestId('fnd-card')
    expect(
      within(card).getByRole('link', { name: /Open the artifact this is about/ }),
    ).toHaveAttribute('href', `/cases/${CASE_ID}/artifacts/subj-1`)
    expect(
      within(card).getByRole('link', { name: /Open the finding record/ }),
    ).toHaveAttribute('href', `/cases/${CASE_ID}/artifacts/fnd-1`)
  })

  /** The values a finding rests on are what an examiner re-reads against the
   *  evidence, and an identifier among them is a pivot like any other. */
  it('reveals the values it rests on, and pivots on the identifiers among them', async () => {
    mock(body())
    const openPivot = renderPage()

    await screen.findByTestId('fnd-card')
    expect(screen.queryByTestId('fnd-evidence')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /values it rests on/ }))

    const evidence = screen.getByTestId('fnd-evidence')
    expect(within(evidence).getByText('si_modified')).toBeInTheDocument()
    // `imphash` is an identifier: a trigger. A timestamp is not.
    await userEvent.click(
      within(evidence).getByText('a9f3b1c0e2d4567890abcdef12345678'),
    )
    expect(openPivot).toHaveBeenCalledWith('a9f3b1c0e2d4567890abcdef12345678')
    expect(
      within(evidence).getByText('2019-03-02T11:14:08Z').tagName,
    ).not.toBe('BUTTON')
  })

  /** A failed load must never render as an empty list: that is a statement
   *  about the case. */
  it('a failed load does not read as a clean case', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/findings`, () =>
        HttpResponse.json({ error: 'boom' }, { status: 500 }),
      ),
    )
    renderPage()
    expect(await screen.findByRole('note')).toHaveTextContent(
      /Nothing here says this case holds none/,
    )
    expect(screen.queryByTestId('fnd-empty')).not.toBeInTheDocument()
  })
})
