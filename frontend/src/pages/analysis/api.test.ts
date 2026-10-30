import { http, HttpResponse } from 'msw'
import { describe, expect, it, vi } from 'vitest'
import { server } from '../../test/server'
import { getAllRecords, getCommsHistogram, getCommsRanking } from './api'

describe('getAllRecords', () => {
  it('fetches pages after the first concurrently and preserves page order', async () => {
    const requested: number[] = []
    let releasePage2: (() => void) | null = null
    const page2Held = new Promise<void>((resolve) => {
      releasePage2 = resolve
    })

    server.use(
      http.get('/api/v1/cases/c1/records', async ({ request }) => {
        const page = Number(new URL(request.url).searchParams.get('page'))
        requested.push(page)
        // Hold page 2 open; if later pages were fetched sequentially they would
        // never be requested until this resolves.
        if (page === 2) await page2Held
        return HttpResponse.json({
          records: [
            {
              id: `r${page}`,
              parent_id: null,
              artifact_type: 'ParsedRecord',
              metadata: { page },
            },
          ],
          total: 5,
          page,
          page_size: 1,
          type: 't',
        })
      }),
    )

    const promise = getAllRecords('c1', 't', { pageSize: 1, maxPages: 8 })

    // Page 3 is requested while page 2 is still held → the pages after the first
    // fan out concurrently (this times out on a sequential walk).
    await vi.waitFor(() => expect(requested).toContain(3))
    expect(requested).toContain(2)

    releasePage2!()
    const result = await promise

    // 5 pages of one record each, concatenated in page order.
    expect(
      result.records.map((r) => (r.metadata as { page: number }).page),
    ).toEqual([1, 2, 3, 4, 5])
    expect(result.total).toBe(5)
    expect(result.truncated).toBe(false)
  })
})

/**
 * The most-contacted league table used to be counted in the browser over the
 * capped slice the correlation page happens to have loaded. `getCommsRanking`
 * is the wire half of the replacement, and its whole job is to keep four
 * different populations apart on the way in: the contacts (narrowed by `q`),
 * the distinct-correspondent count (narrowed by `q`, not by the limit), and the
 * case-level record counts (narrowed by the channel only). A field the server
 * did not send must arrive as "not stated" rather than as zero — a ranking that
 * silently claims "0 calls were recorded with no number" is exactly the kind of
 * unfounded assertion this endpoint exists to remove.
 */
describe('getCommsRanking', () => {
  const BODY = {
    contacts: [
      { contact: '447796268670@s.whatsapp.net', count: 36166 },
      { contact: 'alice@example.com', count: 12 },
    ],
    limit: 20,
    has_more: true,
    distinct_contacts: 4211,
    by_type: [
      ['WhatsApp', 78221],
      ['iMessage', 15041],
    ],
    total_records: 93338,
    summary_records: 12,
    unrankable_records: 40,
    records_without_counterparty: 25,
  }

  it('sends the channel, needle and limit, and carries every population through', async () => {
    let seen: URL | null = null
    server.use(
      http.get('/api/v1/cases/c1/comms/ranking', ({ request }) => {
        seen = new URL(request.url)
        return HttpResponse.json(BODY)
      }),
    )

    const ranking = await getCommsRanking('c1', {
      channel: 'AndroidSms',
      q: 'ali',
      limit: 8,
    })

    expect(seen!.searchParams.get('channel')).toBe('AndroidSms')
    expect(seen!.searchParams.get('q')).toBe('ali')
    expect(seen!.searchParams.get('limit')).toBe('8')
    expect(ranking.contacts).toEqual(BODY.contacts)
    expect(ranking.distinct_contacts).toBe(4211)
    expect(ranking.by_type).toEqual([
      ['WhatsApp', 78221],
      ['iMessage', 15041],
    ])
    expect(ranking.total_records).toBe(93338)
    expect(ranking.summary_records).toBe(12)
    expect(ranking.unrankable_records).toBe(40)
    expect(ranking.records_without_counterparty).toBe(25)
    expect(ranking.has_more).toBe(true)
  })

  it('omits the optional parameters rather than sending empty ones', async () => {
    let seen: URL | null = null
    server.use(
      http.get('/api/v1/cases/c1/comms/ranking', ({ request }) => {
        seen = new URL(request.url)
        return HttpResponse.json({ ...BODY, contacts: [] })
      }),
    )

    await getCommsRanking('c1', {})

    expect(seen!.searchParams.has('channel')).toBe(false)
    expect(seen!.searchParams.has('q')).toBe(false)
  })

  it('reports a count the server did not send as unknown, never as zero', async () => {
    server.use(
      http.get('/api/v1/cases/c1/comms/ranking', () =>
        HttpResponse.json({ contacts: [{ contact: 'a', count: 1 }] }),
      ),
    )

    const ranking = await getCommsRanking('c1', {})

    expect(ranking.distinct_contacts).toBeNull()
    expect(ranking.total_records).toBeNull()
    expect(ranking.summary_records).toBeNull()
    expect(ranking.unrankable_records).toBeNull()
    expect(ranking.records_without_counterparty).toBeNull()
    expect(ranking.by_type).toBeNull()
    // Absent is not false: the caller must not print "this is the whole list".
    expect(ranking.has_more).toBeNull()
  })

  it('rejects a body whose contacts are not a ranking', async () => {
    // A malformed body has to throw so the page falls back to its own labelled
    // slice ranking. Coercing it would put invented rows on screen under the
    // word "exact".
    server.use(
      http.get('/api/v1/cases/c1/comms/ranking', () =>
        HttpResponse.json({ contacts: [{ contact: 'a' }] }),
      ),
    )

    await expect(getCommsRanking('c1', {})).rejects.toThrow(/contacts/)
  })

  it('reports a by_type it cannot read as unknown rather than dropping entries', async () => {
    // Dropping the unreadable pairs would understate the population the
    // ranking covers, and the note under the bars states that population.
    server.use(
      http.get('/api/v1/cases/c1/comms/ranking', () =>
        HttpResponse.json({
          contacts: [],
          by_type: [['WhatsApp', 10], ['iMessage']],
        }),
      ),
    )

    expect((await getCommsRanking('c1', {})).by_type).toBeNull()
  })
})

/**
 * The volume-over-time histogram (LIVE-024's sibling).
 *
 * A histogram is a claim about WHEN things happened, so the wire reader's job
 * is to refuse anything it cannot stand over. Two kinds of refusal live here.
 * A body whose buckets are not buckets throws, exactly as the ranking does,
 * because the caller's fallback is its own honestly-labelled client chart and
 * that is far better than invented bars under the word "exact". A body whose
 * own stated invariants contradict each other ALSO throws: bars that do not sum
 * to the number of records the same response says were placed are not a smaller
 * answer, they are an answer nobody can quote.
 *
 * And every count is read as "not stated" when it is absent. A count the server
 * did not send is not a count of zero — "no record was unreadable" and "the
 * server said nothing about unreadable records" are different claims about the
 * evidence, and only one of them is ours to make.
 */
describe('getCommsHistogram', () => {
  const BODY = {
    buckets: [
      { bucket_start_secs: 1709424000, count: 400, rescued_count: 3 },
      { bucket_start_secs: 1709510400, count: 12, rescued_count: 0 },
    ],
    bucket_seconds: 86400,
    min_ts_secs: 1709424000,
    max_ts_secs: 1709596800,
    total_records: 93338,
    matched_records: 762,
    unreadable_metadata: 1,
    not_a_message: 12,
    unplaceable_absent: 40,
    unplaceable_value: 297,
    placed_by_rescue: 3,
    placed_as_written: 409,
    by_type_unplaceable: [
      ['EmailMessage', 289],
      ['CallLog', 8],
    ],
  }

  it('sends the channel, needle, contact and bucket target, and carries every population through', async () => {
    let seen: URL | null = null
    server.use(
      http.get('/api/v1/cases/c1/comms/histogram', ({ request }) => {
        seen = new URL(request.url)
        return HttpResponse.json(BODY)
      }),
    )

    const h = await getCommsHistogram('c1', {
      channel: 'AndroidSms',
      q: 'ali',
      contact: 'alice',
      buckets: 48,
    })

    expect(seen!.searchParams.get('channel')).toBe('AndroidSms')
    expect(seen!.searchParams.get('q')).toBe('ali')
    expect(seen!.searchParams.get('contact')).toBe('alice')
    expect(seen!.searchParams.get('buckets')).toBe('48')
    expect(h.buckets).toEqual(BODY.buckets)
    expect(h.bucket_seconds).toBe(86400)
    expect(h.min_ts_secs).toBe(1709424000)
    expect(h.max_ts_secs).toBe(1709596800)
    expect(h.total_records).toBe(93338)
    expect(h.matched_records).toBe(762)
    expect(h.unreadable_metadata).toBe(1)
    expect(h.not_a_message).toBe(12)
    expect(h.unplaceable_absent).toBe(40)
    expect(h.unplaceable_value).toBe(297)
    expect(h.placed_by_rescue).toBe(3)
    expect(h.placed_as_written).toBe(409)
    expect(h.by_type_unplaceable).toEqual([
      ['EmailMessage', 289],
      ['CallLog', 8],
    ])
  })

  it('omits the optional parameters rather than sending empty ones', async () => {
    let seen: URL | null = null
    server.use(
      http.get('/api/v1/cases/c1/comms/histogram', ({ request }) => {
        seen = new URL(request.url)
        return HttpResponse.json(BODY)
      }),
    )

    await getCommsHistogram('c1', {})

    expect(seen!.searchParams.has('channel')).toBe(false)
    expect(seen!.searchParams.has('q')).toBe(false)
    expect(seen!.searchParams.has('contact')).toBe(false)
  })

  it('carries the whole census on the empty-extent path', async () => {
    // Four states have to be told apart from the payload alone, and three of
    // them return no bars at all. A reader that treated "no buckets" as "no
    // answer" would collapse "this case has no communications", "records exist
    // and none could be placed" and "your filter matched nothing" into one
    // blank chart.
    server.use(
      http.get('/api/v1/cases/c1/comms/histogram', () =>
        HttpResponse.json({
          buckets: [],
          bucket_seconds: null,
          min_ts_secs: null,
          max_ts_secs: null,
          total_records: 93338,
          matched_records: 329,
          unreadable_metadata: 0,
          not_a_message: 12,
          unplaceable_absent: 40,
          unplaceable_value: 277,
          placed_by_rescue: 0,
          placed_as_written: 0,
          by_type_unplaceable: [['EmailMessage', 277]],
        }),
      ),
    )

    const h = await getCommsHistogram('c1', {})

    expect(h.buckets).toEqual([])
    expect(h.bucket_seconds).toBeNull()
    expect(h.min_ts_secs).toBeNull()
    expect(h.matched_records).toBe(329)
    expect(h.unplaceable_value).toBe(277)
  })

  it('reports a count the server did not send as unknown, never as zero', async () => {
    server.use(
      http.get('/api/v1/cases/c1/comms/histogram', () =>
        HttpResponse.json({ buckets: [] }),
      ),
    )

    const h = await getCommsHistogram('c1', {})

    expect(h.bucket_seconds).toBeNull()
    expect(h.min_ts_secs).toBeNull()
    expect(h.max_ts_secs).toBeNull()
    expect(h.total_records).toBeNull()
    expect(h.matched_records).toBeNull()
    expect(h.unreadable_metadata).toBeNull()
    expect(h.not_a_message).toBeNull()
    expect(h.unplaceable_absent).toBeNull()
    expect(h.unplaceable_value).toBeNull()
    expect(h.placed_by_rescue).toBeNull()
    expect(h.placed_as_written).toBeNull()
    expect(h.by_type_unplaceable).toBeNull()
  })

  it('reads a bucket that did not state its rescued count as unknown', async () => {
    server.use(
      http.get('/api/v1/cases/c1/comms/histogram', () =>
        HttpResponse.json({
          buckets: [{ bucket_start_secs: 1709424000, count: 4 }],
          bucket_seconds: 86400,
          min_ts_secs: 1709424000,
        }),
      ),
    )

    expect((await getCommsHistogram('c1', {})).buckets[0].rescued_count).toBeNull()
  })

  it('rejects a body whose buckets are not buckets', async () => {
    server.use(
      http.get('/api/v1/cases/c1/comms/histogram', () =>
        HttpResponse.json({ buckets: [{ count: 4 }] }),
      ),
    )

    await expect(getCommsHistogram('c1', {})).rejects.toThrow(/bucket/i)
  })

  it('rejects bars it cannot state the width of', async () => {
    // A bar whose width is unknown can only be drawn as an instant, and an
    // instant is the one thing a bucket is not.
    server.use(
      http.get('/api/v1/cases/c1/comms/histogram', () =>
        HttpResponse.json({
          buckets: [{ bucket_start_secs: 1709424000, count: 4 }],
          min_ts_secs: 1709424000,
        }),
      ),
    )

    await expect(getCommsHistogram('c1', {})).rejects.toThrow(/width|bucket_seconds/i)
  })

  it('refuses a census that does not add up to the records it says matched', async () => {
    server.use(
      http.get('/api/v1/cases/c1/comms/histogram', () =>
        HttpResponse.json({ ...BODY, matched_records: 999 }),
      ),
    )

    await expect(getCommsHistogram('c1', {})).rejects.toThrow(/census/i)
  })

  it('refuses bars that do not sum to the records it says were placed', async () => {
    server.use(
      http.get('/api/v1/cases/c1/comms/histogram', () =>
        HttpResponse.json({
          ...BODY,
          buckets: [{ bucket_start_secs: 1709424000, count: 11, rescued_count: 3 }],
        }),
      ),
    )

    await expect(getCommsHistogram('c1', {})).rejects.toThrow(/bars/i)
  })

  it('refuses a rescued total the bars disagree with', async () => {
    // The rescued count is the one number that lets the chart avoid presenting
    // an assumed instant as a read one. A response whose bars and whose total
    // disagree about it cannot be quoted for either.
    server.use(
      http.get('/api/v1/cases/c1/comms/histogram', () =>
        HttpResponse.json({
          ...BODY,
          buckets: [
            { bucket_start_secs: 1709424000, count: 400, rescued_count: 0 },
            { bucket_start_secs: 1709510400, count: 12, rescued_count: 0 },
          ],
        }),
      ),
    )

    await expect(getCommsHistogram('c1', {})).rejects.toThrow(/rescued/i)
  })

  it('refuses a matched population larger than the case it was drawn from', async () => {
    server.use(
      http.get('/api/v1/cases/c1/comms/histogram', () =>
        HttpResponse.json({ ...BODY, total_records: 10 }),
      ),
    )

    await expect(getCommsHistogram('c1', {})).rejects.toThrow(/case/i)
  })

  it('refuses an extent that contradicts the bars', async () => {
    // Bars with no stated extent, or an extent with no bars, is a response that
    // cannot draw an axis it can defend.
    server.use(
      http.get('/api/v1/cases/c1/comms/histogram', () =>
        HttpResponse.json({ ...BODY, min_ts_secs: null }),
      ),
    )

    await expect(getCommsHistogram('c1', {})).rejects.toThrow(/extent/i)
  })

  it('reports a by_type_unplaceable it cannot read as unknown rather than dropping entries', async () => {
    server.use(
      http.get('/api/v1/cases/c1/comms/histogram', () =>
        HttpResponse.json({
          buckets: [],
          by_type_unplaceable: [['EmailMessage', 10], ['CallLog']],
        }),
      ),
    )

    expect((await getCommsHistogram('c1', {})).by_type_unplaceable).toBeNull()
  })
})
