import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { EventHistogram, TimeHistogram, type HistoBucket } from './RichCharts'

const DAY = 86_400_000
/** 2024-03-03 00:00:00 UTC, a round instant so the assertions can name it. */
const T0 = Date.UTC(2024, 2, 3)

/** Every `<title>` the chart drew, in bar order. */
const tooltips = () =>
  [...document.querySelectorAll('svg title')].map((t) => t.textContent ?? '')

/** The chart's own sentences, in DOM order. */
const notes = () =>
  [...document.querySelectorAll('.rv-histo [role="note"]')].map(
    (n) => n.textContent ?? '',
  )

/**
 * The volume chart is the one element on these pages an examiner reads at a
 * glance, and three of its behaviours were assertions it was not entitled to
 * make.
 *
 * It returned `null` for an empty set, so a filter state in which every record
 * was untimed drew nothing at all — a screen indistinguishable from a period in
 * which nothing happened. It dropped untimed records with no counter anywhere,
 * while the toolbar beside it counted them, so the number an examiner read as
 * the chart's total was already short by an unstated amount. And its tooltip
 * printed the instant each bucket STARTS at as though that were when the events
 * occurred, over buckets that can be weeks wide.
 */
describe('TimeHistogram with nothing to draw', () => {
  it('says so in place of the bars rather than rendering nothing', () => {
    const { container } = render(<TimeHistogram times={[]} />)

    expect(container.querySelector('.rv-histo')).not.toBeNull()
    expect(notes().join(' ')).toMatch(/could read/i)
    // The sentence an empty chart must always carry: absence of bars is not
    // evidence of absence of events.
    expect(notes().join(' ')).toMatch(/not a statement that nothing happened/i)
  })

  it('tells an empty view apart from a view whose records could not be placed', () => {
    const noRecords = render(<TimeHistogram times={[]} untimed={0} />)
    expect(notes().join(' ')).toMatch(/no records in view/i)
    expect(notes().join(' ')).not.toMatch(/could not be placed|could read/i)
    noRecords.unmount()

    render(<TimeHistogram times={[]} untimed={5} />)
    expect(notes().join(' ')).toMatch(/5/)
    expect(notes().join(' ')).toMatch(/could read/i)
  })
})

describe('TimeHistogram untimed counter', () => {
  it('states the records it left off the chart', () => {
    render(<TimeHistogram times={[T0, T0 + DAY]} untimed={40} />)

    const said = notes().join(' ')
    expect(said).toMatch(/40/)
    expect(said).toMatch(/not on this chart|not drawn/i)
    // And the placed count, so the two numbers on screen add up to something.
    expect(said).toMatch(/\b2\b/)
  })

  it('stays silent when every record in view was placed', () => {
    render(<TimeHistogram times={[T0, T0 + DAY]} untimed={0} />)

    expect(notes().join(' ')).not.toMatch(/not on this chart|not drawn/i)
  })

  it('says nothing about untimed records when it was told nothing', () => {
    // The two viewers that draw this chart hand it timestamps and no census.
    // Inventing a zero there would put "0 records carried no time" on screen as
    // a finding about the evidence.
    render(<TimeHistogram times={[T0, T0 + DAY]} />)

    expect(notes().join(' ')).not.toMatch(/carried no time|not on this chart/i)
  })
})

describe('bar tooltips', () => {
  it('state the period a bar covers, never the instant it starts at', () => {
    // 48 bars over 48 days is one bar per day. A tooltip reading
    // "2024-03-03 00:00:00 UTC — 412 events" invites "412 events at midnight on
    // 3 March"; over a 22-day bucket that sentence is wrong by three weeks.
    render(<TimeHistogram times={[T0, T0 + 48 * DAY]} />)

    const first = tooltips()[0]
    expect(first).toMatch(/2024-03-03 00:00:00 UTC/)
    expect(first).toMatch(/2024-03-04 00:00:00 UTC/)
    expect(first).toMatch(/ to /)
    // The end of the range is excluded, and saying so is the difference between
    // a bar that owns midnight and the one after it that does.
    expect(first).toMatch(/end excluded/i)
  })
})

describe('EventHistogram', () => {
  const bucket = (
    startMs: number,
    count: number,
    rescued: number | null = null,
  ): HistoBucket => ({ startMs, count, rescued })

  it('fills interior gaps so a quiet week is drawn as quiet, not as absent', () => {
    // The server omits empty buckets. Drawing only what it sent would put two
    // adjacent bars a fortnight apart and label the axis as though they were
    // consecutive.
    render(
      <EventHistogram
        buckets={[bucket(T0, 5), bucket(T0 + 3 * DAY, 7)]}
        bucketMs={DAY}
      />,
    )

    const drawn = tooltips()
    expect(drawn).toHaveLength(4)
    expect(drawn[0]).toMatch(/5 events/)
    expect(drawn[1]).toMatch(/\b0 events\b/)
    expect(drawn[2]).toMatch(/\b0 events\b/)
    expect(drawn[3]).toMatch(/7 events/)
  })

  // ---- UI-007: the shared outlier focus, used here by every rich viewer
  // chart AND by the communications "Volume over time" chart ----------------

  /** One stray old event, then thirty days of real activity long after it. */
  const skewed = () => {
    const outlier = T0 - 400 * DAY
    return [
      bucket(outlier, 1),
      ...Array.from({ length: 30 }, (_, i) => bucket(T0 + i * DAY, 100)),
    ]
  }

  it('focuses the axis on the mass rather than on one old timestamp', () => {
    render(<EventHistogram buckets={skewed()} bucketMs={DAY} />)

    // Thirty bars of real activity, not one bar and four hundred empty slots.
    expect(tooltips()).toHaveLength(30)
    expect(tooltips()[0]).toMatch(/100 events/)
  })

  it('states what the focused axis left out, and where it was', () => {
    render(<EventHistogram buckets={skewed()} bucketMs={DAY} />)

    const note = screen.getByTestId('rv-histo-focus')
    expect(note.textContent).toMatch(/1 earlier event/)
    expect(note.textContent).toMatch(/counted, not discarded/i)

    // And the same sentence reaches a screen reader and a printed exhibit,
    // which cannot hover a tooltip.
    const summary = screen.getByTestId('rv-histo-summary')
    expect(summary.textContent).toMatch(/focused on where the events are/i)
    expect(summary.textContent).toMatch(/1 further event/)
  })

  it('says nothing about focusing when it focused on nothing', () => {
    render(
      <EventHistogram
        buckets={[bucket(T0, 5), bucket(T0 + DAY, 7)]}
        bucketMs={DAY}
      />,
    )
    expect(screen.queryByTestId('rv-histo-focus')).toBeNull()
    expect(screen.getByTestId('rv-histo-summary').textContent).not.toMatch(
      /focused/i,
    )
  })

  it('does not focus away a genuine early cluster merely for being early', () => {
    // The earliest activity in a case is often the most interesting thing on
    // it. The window narrows only when an end is BOTH a small share of the
    // events AND separated from the mass by a long gap; a contiguous run is
    // neither, and must be drawn.
    const contiguous = Array.from({ length: 30 }, (_, i) =>
      bucket(T0 + i * DAY, i < 3 ? 1 : 100),
    )
    render(<EventHistogram buckets={contiguous} bucketMs={DAY} />)

    expect(tooltips()).toHaveLength(30)
    expect(screen.queryByTestId('rv-histo-focus')).toBeNull()
  })

  it('names the records a bar placed only by assuming their unit', () => {
    // A rescued instant rests on an assumption about which unit the parser
    // wrote. Drawing it beside a value read to contract without saying so
    // presents the weaker fact as the stronger one.
    render(<EventHistogram buckets={[bucket(T0, 10, 3)]} bucketMs={DAY} />)

    expect(tooltips()[0]).toMatch(/3 of them/i)
    expect(tooltips()[0]).toMatch(/assuming which unit/i)
  })

  it('claims nothing about rescue where the count was not stated', () => {
    render(<EventHistogram buckets={[bucket(T0, 10, null)]} bucketMs={DAY} />)

    expect(tooltips()[0]).not.toMatch(/assuming which unit/i)
  })

  it('draws the supplied empty sentence in place of the bars', () => {
    render(
      <EventHistogram
        buckets={[]}
        bucketMs={null}
        empty="Your filter matched nothing in this case."
      />,
    )

    expect(
      screen.getByText('Your filter matched nothing in this case.'),
    ).toBeInTheDocument()
    expect(tooltips()).toHaveLength(0)
  })

  it('says when it could not draw every bar', () => {
    // Silently capping the bars would shorten the chart's right-hand edge and
    // leave the axis claiming an extent the drawing does not cover.
    render(
      <EventHistogram
        buckets={[bucket(T0, 1), bucket(T0 + 5000 * DAY, 1)]}
        bucketMs={DAY}
      />,
    )

    expect(notes().join(' ')).toMatch(/2,000/)
    expect(notes().join(' ')).toMatch(/not drawn|only the first/i)
  })

  it('groups every figure the same way whatever the runtime locale', () => {
    // These counts are quoted into statements. On a de-DE runner a bare
    // toLocaleString puts "93.338" beside the pinned "93,338" elsewhere on the
    // page, where the first reads as ninety-three point three.
    vi.spyOn(Number.prototype, 'toLocaleString').mockImplementation(function (
      this: number,
    ) {
      return new Intl.NumberFormat('de-DE').format(Number(this))
    })

    render(<EventHistogram buckets={[bucket(T0, 93338, 4211)]} bucketMs={DAY} />)

    expect(tooltips()[0]).toMatch(/93,338/)
    expect(tooltips()[0]).toMatch(/4,211/)
    expect(tooltips()[0]).not.toMatch(/93\.338|4\.211/)

    vi.restoreAllMocks()
  })

  it('states the extent and the bar width where a reader cannot hover', () => {
    // A tooltip is not available to a screen reader or to a printed exhibit.
    render(<EventHistogram buckets={[bucket(T0, 5)]} bucketMs={DAY} />)

    const summary = screen.getByTestId('rv-histo-summary').textContent ?? ''
    expect(summary).toMatch(/2024-03-03 00:00:00 UTC/)
    expect(summary).toMatch(/2024-03-04 00:00:00 UTC/)
    expect(summary).toMatch(/5 events/)
    expect(summary).toMatch(/1 day/)
    expect(summary).toMatch(/end excluded/i)
  })
})
