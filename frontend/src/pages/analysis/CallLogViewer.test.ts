import { describe, expect, it } from 'vitest'
import type { ParsedRecord, RecordMetadata } from './api'
import { deriveCallCounts } from './CallLogViewer'

function call(direction: string): ParsedRecord {
  return {
    id: Math.random().toString(36).slice(2),
    parent_id: null,
    artifact_type: 'ParsedRecord',
    metadata: { subtype: 'call', direction },
  }
}

describe('deriveCallCounts (BUG-176)', () => {
  it('derives totals from the loaded call rows, not the summary record', () => {
    const calls = [
      call('incoming'),
      call('incoming'),
      call('outgoing'),
      call('missed'),
      call('unknown'), // still counted in the total
    ]
    // A zero/empty parser summary must not zero the header when rows exist.
    const emptySummary: RecordMetadata = { subtype: 'summary' }
    const counts = deriveCallCounts(calls, emptySummary)
    expect(counts).toEqual({
      total: 5,
      incoming: 2,
      outgoing: 1,
      missed: 1,
    })
  })

  it('uses the parser total only when it exceeds the loaded (paginated) rows', () => {
    const calls = [call('incoming'), call('outgoing')]
    const counts = deriveCallCounts(calls, {
      subtype: 'summary',
      call_count: 100,
    })
    // Total reflects the larger parser figure; per-direction stays row-derived.
    expect(counts.total).toBe(100)
    expect(counts.incoming).toBe(1)
    expect(counts.outgoing).toBe(1)
    expect(counts.missed).toBe(0)
  })

  it('falls back to the row count with no summary record', () => {
    const counts = deriveCallCounts([call('missed'), call('missed')])
    expect(counts.total).toBe(2)
    expect(counts.missed).toBe(2)
  })
})
