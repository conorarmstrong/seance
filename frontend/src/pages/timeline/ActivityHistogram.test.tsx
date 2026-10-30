import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ActivityHistogram } from './ActivityHistogram'
import type { TimelineHistogram } from './api'

const noop = () => {}

/** jsdom reports zero-size rects; give the brush surface a real geometry. */
function mockPlotRect(plot: HTMLElement, width: number) {
  plot.getBoundingClientRect = () =>
    ({
      left: 0,
      top: 0,
      width,
      height: 80,
      right: width,
      bottom: 80,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    }) as DOMRect
}

describe('ActivityHistogram', () => {
  it('renders the bars and the span they cover', () => {
    const data: TimelineHistogram = {
      min_ts: 1000,
      max_ts: 1200,
      bucket_seconds: 100,
      buckets: [
        { start: 1000, count: 3 },
        { start: 1100, count: 5 },
      ],
    }
    render(
      <ActivityHistogram
        data={data}
        isError={false}
        error={null}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    )
    expect(screen.getByText(/8 events between/)).toBeInTheDocument()
  })

  it('says a failed load failed rather than leaving the band blank', () => {
    // The failure used to reach a console.warn and nothing else, so the chart
    // simply was not there. An empty band and a window with no activity in it
    // look identical, and this chart is the control every date filter on the
    // page is set from.
    render(
      <ActivityHistogram
        data={undefined}
        isError={true}
        error={new Error('timeline index unavailable')}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    )
    const note = screen.getByTestId('tl-histogram-error')
    expect(note.textContent).toMatch(/could not be loaded/i)
    expect(note.textContent).toMatch(/timeline index unavailable/)
    expect(note.textContent).toMatch(/not a period with no activity/i)
    expect(screen.queryByText(/No timeline activity/)).toBeNull()
  })

  it('subscribes the drag handlers once per drag, not once per mouse move', () => {
    // The drag effect had no dependency array, and `onMove` sets state for
    // every pixel of travel: each of those renders tore down and re-attached
    // mousemove/mouseup/keydown on window, on the control the whole page's date
    // filtering is driven from. One subscription must cover the whole drag.
    const data: TimelineHistogram = {
      min_ts: 1000,
      max_ts: 1200,
      bucket_seconds: 100,
      buckets: [
        { start: 1000, count: 3 },
        { start: 1100, count: 5 },
      ],
    }
    const { container } = render(
      <ActivityHistogram
        data={data}
        isError={false}
        error={null}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    )
    const plot = container.querySelector('.tl-hist-plot') as HTMLElement
    mockPlotRect(plot, 400)
    const addListener = vi.spyOn(window, 'addEventListener')

    fireEvent.mouseDown(plot, { clientX: 40, button: 0 })
    for (const clientX of [80, 120, 160, 200, 240]) {
      fireEvent.mouseMove(window, { clientX })
    }

    const subscriptions = addListener.mock.calls.filter(
      ([type]) => type === 'mousemove',
    )
    expect(subscriptions).toHaveLength(1)

    fireEvent.mouseUp(window, { clientX: 240 })
    addListener.mockRestore()
  })

  it('brushes the domain on screen when the mouse is released, not the one it went down on', () => {
    // Attaching the handlers once per drag is only correct if they read the
    // domain live. A refetch landing mid-drag redraws the bars on a new domain,
    // and the range the examiner releases has to be the one under the pointer
    // then -- otherwise the filter says a window of time the chart never showed.
    const onBrush = vi.fn()
    const first: TimelineHistogram = {
      min_ts: 1000,
      max_ts: 1200,
      bucket_seconds: 100,
      buckets: [
        { start: 1000, count: 3 },
        { start: 1100, count: 5 },
      ],
    }
    const second: TimelineHistogram = {
      min_ts: 2000,
      max_ts: 2200,
      bucket_seconds: 100,
      buckets: [
        { start: 2000, count: 1 },
        { start: 2100, count: 4 },
      ],
    }
    const chart = (data: TimelineHistogram) => (
      <ActivityHistogram
        data={data}
        isError={false}
        error={null}
        hasRange={false}
        onBrush={onBrush}
        onClearRange={noop}
      />
    )
    const { container, rerender } = render(chart(first))
    const plot = container.querySelector('.tl-hist-plot') as HTMLElement
    mockPlotRect(plot, 400)

    fireEvent.mouseDown(plot, { clientX: 100, button: 0 })
    rerender(chart(second))
    fireEvent.mouseUp(window, { clientX: 300 })

    // 25%..75% of the domain now drawn (2000..2200).
    expect(onBrush).toHaveBeenCalledWith(2050, 2150)
  })

  // ---- UI-007: outlier timestamps must not squash the chart ---------------

  /**
   * One stray old timestamp, and the real activity nine years later.
   *
   * Shaped the way the server actually answers: `get_timeline_histogram` picks
   * `bucket_seconds` by dividing the full extent into ~120 buckets and rounding
   * up to a friendly unit, so a span of that width comes back in ~month-wide
   * buckets. Before the fix the axis ran from the outlier and the thirty months
   * of real activity sat crushed at the right-hand edge.
   */
  const MONTH = 2_629_800

  function skewed(): TimelineHistogram {
    const first = 1_420_070_400 // 2015-01-01
    const mass = first + 100 * MONTH
    const buckets = [{ start: first, count: 1 }]
    for (let i = 0; i < 30; i++) {
      buckets.push({ start: mass + i * MONTH, count: 100 })
    }
    return {
      min_ts: first,
      max_ts: mass + 30 * MONTH,
      bucket_seconds: MONTH,
      buckets,
    }
  }

  it('focuses the axis on where the events are instead of on an outlier', () => {
    render(
      <ActivityHistogram
        data={skewed()}
        isError={false}
        error={null}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    )

    // The drawn axis starts at the mass, not at the 2015 outlier, and the
    // thirty months of real activity are thirty bars rather than one.
    const start = document.querySelector('.tl-hist-axis-start')
    expect(start?.textContent).not.toMatch(/^2015/)
    expect(start?.textContent).toMatch(/^202/)
    expect(document.querySelectorAll('.tl-hist-bar').length).toBe(30)
  })

  it('discloses the events the focused axis leaves out, and where they are', () => {
    render(
      <ActivityHistogram
        data={skewed()}
        isError={false}
        error={null}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    )

    const note = screen.getByTestId('tl-histogram-focus')
    expect(note.textContent).toMatch(/1 earlier event/)
    expect(note.textContent).toMatch(/2015/)
    expect(note.textContent).toMatch(/counted here/)
  })

  it('counts every event in the summary, including the ones it did not draw', () => {
    render(
      <ActivityHistogram
        data={skewed()}
        isError={false}
        error={null}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    )

    // 30 x 100 drawn + the 2015 outlier that is not. A count that excluded the
    // outlier would sit beside the full date range and under-report the case.
    expect(screen.getByText(/3001 events between/)).toBeInTheDocument()
  })

  it('says nothing about focusing when nothing was left out', () => {
    const data: TimelineHistogram = {
      min_ts: 1000,
      max_ts: 1200,
      bucket_seconds: 100,
      buckets: [
        { start: 1000, count: 3 },
        { start: 1100, count: 5 },
      ],
    }
    render(
      <ActivityHistogram
        data={data}
        isError={false}
        error={null}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    )
    expect(screen.queryByTestId('tl-histogram-focus')).toBeNull()
    expect(screen.getByText(/^8 events between/)).toBeInTheDocument()
  })

  it('brushes against the drawn domain, not the unfocused one', () => {
    // The range an examiner drags out has to mean the part of the chart they
    // can see. Committing against the unfocused domain would return a range
    // nine years wide for a drag across the visible bars.
    const onBrush = vi.fn()
    const { container } = render(
      <ActivityHistogram
        data={skewed()}
        isError={false}
        error={null}
        hasRange={false}
        onBrush={onBrush}
        onClearRange={noop}
      />,
    )
    const plot = container.querySelector('.tl-hist-plot') as HTMLElement
    mockPlotRect(plot, 1000)

    fireEvent.mouseDown(plot, { button: 0, clientX: 100 })
    fireEvent.mouseUp(window, { clientX: 900 })

    expect(onBrush).toHaveBeenCalledTimes(1)
    const [from, to] = onBrush.mock.calls[0]
    // Both ends land in the mass, well after the 2015 outlier.
    expect(from).toBeGreaterThan(1_420_070_400 + 90 * MONTH)
    expect(to).toBeGreaterThan(from)
  })
})

describe('a server-focused response (UI-010)', () => {
  // The server picked the window and re-queried the buckets at a width chosen
  // for it, so the response holds ONLY the window's bars and states what it
  // left out. Three things have to hold: the bars are drawn as they arrived,
  // the count beside the extent still counts the whole case, and the note
  // quotes the extent rather than the window.
  const focused: TimelineHistogram = {
    // The case spans four decades because of one 1980 stamp...
    min_ts: 315_532_800,
    max_ts: 1_700_006_400,
    // ...but these bars are one hour apart, which is the resolution the
    // unfocused extent could never have produced.
    bucket_seconds: 3600,
    buckets: [
      { start: 1_700_000_000, count: 40 },
      { start: 1_700_003_600, count: 60 },
    ],
    focus: {
      from: 1_700_000_000,
      to: 1_700_007_200,
      events_before: 1,
      events_after: 0,
    },
  }

  it('draws the window it was given without narrowing it again', () => {
    render(
      <ActivityHistogram
        data={focused}
        isError={false}
        error={null}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    )
    // Two bars in, two bars out: applying the focus rule a second time to an
    // already-focused chart is how two passes of one rule disagree.
    expect(document.querySelectorAll('.tl-hist-bar').length).toBe(2)
  })

  it('counts the events the server left out, and names the whole extent', () => {
    render(
      <ActivityHistogram
        data={focused}
        isError={false}
        error={null}
        hasRange={false}
        onBrush={noop}
        onClearRange={noop}
      />,
    )
    // 100 drawn + 1 outside. Counting only the drawn bars would put a smaller
    // number beside the wider range.
    expect(screen.getByText(/101 events between/)).toBeInTheDocument()
    const note = screen.getByTestId('tl-histogram-focus')
    expect(note.textContent).toMatch(/1 earlier event/)
    expect(note.textContent).toMatch(/1980/)
    expect(note.textContent).toMatch(/still in every export/)
  })
})
