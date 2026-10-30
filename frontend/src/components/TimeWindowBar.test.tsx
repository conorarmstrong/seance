import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { server } from '../test/server'
import { TimeWindowBar } from './TimeWindowBar'
import {
  TimeWindowCtx,
  TimeWindowProvider,
  useTimeWindow,
} from '../app/TimeWindowContext'
import type { TimeWindow } from '../app/TimeWindowContext'

const DAY = 86_400
/** 2024-01-01T00:00:00Z */
const START = 1_704_067_200

function mockHistogram(body: unknown) {
  server.use(
    http.get('/api/v1/cases/c1/timeline/histogram', () =>
      HttpResponse.json(body as Parameters<typeof HttpResponse.json>[0]),
    ),
  )
}

const THREE_DAYS = {
  min_ts: START,
  max_ts: START + 3 * DAY,
  bucket_seconds: DAY,
  buckets: [
    { start: START, count: 10 },
    { start: START + DAY, count: 4 },
    { start: START + 2 * DAY, count: 7 },
  ],
}

/** The bar under a provider, so clicking really sets the window. */
function renderWithProvider() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <TimeWindowProvider caseId="c1">
          <TimeWindowBar caseId="c1" />
        </TimeWindowProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** The bar with an observable api, to assert what it asks for. */
function renderWithApi(window: TimeWindow | null) {
  const setWindow = vi.fn()
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <TimeWindowCtx.Provider value={{ window, setWindow }}>
          <TimeWindowBar caseId="c1" />
        </TimeWindowCtx.Provider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return setWindow
}

describe('TimeWindowBar (§1.1)', () => {
  it('narrows the case to the bucket that was clicked', async () => {
    mockHistogram(THREE_DAYS)
    const setWindow = renderWithApi(null)

    // Each bar names its own period, so the control is usable without sight
    // of the chart.
    const bars = await screen.findAllByRole('button', {
      name: /Narrow the case to/,
    })
    expect(bars).toHaveLength(3)
    expect(bars[0]).toHaveAccessibleName(
      'Narrow the case to 2024-01-01: 10 events',
    )
    await userEvent.click(bars[1])
    expect(setWindow).toHaveBeenCalledWith({
      from: START + DAY,
      to: START + 2 * DAY,
    })
  })

  /**
   * The thing narrowing the view was set on another screen and followed the
   * reader here, so it is printed in full rather than left to a chip.
   */
  it('prints the window in force and what it does not mean', async () => {
    mockHistogram(THREE_DAYS)
    renderWithApi({ from: START, to: START + DAY })

    const note = await screen.findByTestId('twb-active')
    expect(note).toHaveTextContent('2024-01-01')
    expect(note).toHaveTextContent('is in force on Timeline')
    // The sentence that stops a narrowed count being read as the case.
    expect(note).toHaveTextContent(
      /a count on one of them is a count inside this window, not a count in the case/,
    )
    // And it says what is NOT narrowed, so a screen outside the list is
    // visibly outside it.
    expect(note).toHaveTextContent(/Nothing outside the Timeline is narrowed/)
  })

  it('clears back to the whole case', async () => {
    mockHistogram(THREE_DAYS)
    renderWithProvider()
    const bars = await screen.findAllByRole('button', {
      name: /Narrow the case to/,
    })
    await userEvent.click(bars[0])
    expect(screen.getByTestId('twb-active')).toBeInTheDocument()

    await userEvent.click(
      screen.getByRole('button', { name: 'Show the whole case' }),
    )
    expect(screen.getByTestId('twb-none')).toHaveTextContent(
      /The whole case is in view/,
    )
  })

  /** The bars inside the window are shaded, so the control shows its own state
   *  on the axis it set it on. */
  it('shades the bars inside the window in force', async () => {
    mockHistogram(THREE_DAYS)
    renderWithApi({ from: START, to: START + DAY })
    const bars = await screen.findAllByRole('button', {
      name: /Narrow the case to/,
    })
    expect(bars[0]).toHaveAttribute('aria-pressed', 'true')
    expect(bars[1]).toHaveAttribute('aria-pressed', 'true')
    expect(bars[2]).toHaveAttribute('aria-pressed', 'false')
  })

  /**
   * A case with no dated evidence has no axis to narrow along, and a control
   * that cannot be used is a control that has to be explained.
   */
  it('renders nothing at all when there is nothing to narrow along', async () => {
    mockHistogram({
      min_ts: null,
      max_ts: null,
      bucket_seconds: null,
      buckets: [],
    })
    renderWithApi(null)
    await new Promise((r) => setTimeout(r, 0))
    expect(screen.queryByTestId('time-window-bar')).not.toBeInTheDocument()
  })

  /**
   * A broken histogram must not put an error band across every screen in the
   * case — but a window already in force is still narrowing them, and saying
   * so matters more than the chart does.
   */
  it('keeps saying what is in force when the chart itself fails to load', async () => {
    server.use(
      http.get('/api/v1/cases/c1/timeline/histogram', () =>
        HttpResponse.json({ error: 'nope' }, { status: 500 }),
      ),
    )
    renderWithApi({ from: START, to: START + DAY })
    expect(await screen.findByTestId('twb-active')).toBeInTheDocument()
    expect(
      screen.queryAllByRole('button', { name: /Narrow the case to/ }),
    ).toHaveLength(0)

    // With no window, a failed chart is silent rather than an error band.
    server.use(
      http.get('/api/v1/cases/c1/timeline/histogram', () =>
        HttpResponse.json({ error: 'nope' }, { status: 500 }),
      ),
    )
    renderWithApi(null)
    await new Promise((r) => setTimeout(r, 0))
    expect(screen.queryByTestId('twb-none')).not.toBeInTheDocument()
  })

  /**
   * A drag backwards is a window. What must never reach a query is
   * `from > to`, which every consumer would answer with an empty population
   * that reads as "nothing happened".
   */
  it('normalises a backwards window rather than passing it on', async () => {
    mockHistogram(THREE_DAYS)
    function Probe() {
      const { window, setWindow } = useTimeWindow()
      return (
        <>
          <button
            type="button"
            onClick={() => setWindow({ from: START + 2 * DAY, to: START })}
          >
            set backwards
          </button>
          <span data-testid="probe">
            {window ? `${window.from}..${window.to}` : 'none'}
          </span>
        </>
      )
    }
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <TimeWindowProvider caseId="c1">
            <Probe />
          </TimeWindowProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    )
    await userEvent.click(screen.getByRole('button', { name: 'set backwards' }))
    expect(screen.getByTestId('probe')).toHaveTextContent(
      `${START}..${START + 2 * DAY}`,
    )
  })
})
