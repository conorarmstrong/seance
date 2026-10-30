// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { densify, gridStart } from './MiniTimeline'

describe('densify', () => {
  it('places sparse buckets at their time slot and fills gaps with 0', () => {
    // minTs=0, bucket=10s, maxTs=40 -> 5 slots (0,10,20,30,40)
    const out = densify(
      [
        { start: 0, count: 3 },
        { start: 20, count: 5 },
        { start: 40, count: 2 },
      ],
      0,
      40,
      10,
    )
    expect(out).toEqual([3, 0, 5, 0, 2])
  })

  it('ignores out-of-range buckets', () => {
    const out = densify([{ start: 1000, count: 9 }], 0, 20, 10)
    expect(out).toEqual([0, 0, 0])
  })

  it('falls back to raw counts when bucketSeconds is unusable', () => {
    expect(densify([{ start: 5, count: 4 }], 0, 10, 0)).toEqual([4])
  })
})

describe('the bucket that contains the first event', () => {
  // UI-027. The server aligns bucket starts to absolute multiples of the bucket
  // width, so the bucket holding the first event normally starts BEFORE it.
  // Indexing the grid from the first event's timestamp put that bucket at -1
  // and dropped it: on the Nitroba capture the dashboard drew 2,576 of 2,864
  // events and told the examiner the missing 288 were "beyond the charted
  // range". They were at the very start of the case — usually the part that
  // matters most.
  it('is drawn, not dropped, when it starts before the first event', () => {
    // First event at 1216691467; the 300s grid puts its bucket at 1216691400.
    const minTs = 1216691467
    const buckets = [
      { start: 1216691400, count: 288 },
      { start: 1216691700, count: 12 },
    ]
    const out = densify(buckets, minTs, 1216692000, 300)
    expect(out.reduce((a, b) => a + b, 0)).toBe(300)
    expect(out[0]).toBe(288)
  })

  it('still drops a bucket that is genuinely out of range', () => {
    // More than one bucket width before the first event: not the first event's
    // bucket, and not part of this chart's range.
    const out = densify([{ start: 0, count: 9 }], 1000, 1020, 10)
    expect(out.reduce((a, b) => a + b, 0)).toBe(0)
  })

  it('anchors the grid on the bucket, not on the event', () => {
    expect(gridStart([{ start: 90, count: 1 }], 100, 60)).toBe(90)
    // A start further back than one width is not the first event's bucket.
    expect(gridStart([{ start: 10, count: 1 }], 100, 60)).toBe(100)
    // No bucket width: nothing to anchor.
    expect(gridStart([{ start: 90, count: 1 }], 100, 0)).toBe(100)
  })
})
