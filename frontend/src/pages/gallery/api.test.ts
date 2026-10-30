import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { collectImageIds, listExifRecords } from './api'

const CASE = 'c1'

/** A files page of `count` rows, claiming another page exists when `more`. */
function filesPage(page: number, count: number, more: boolean) {
  return HttpResponse.json({
    items: Array.from({ length: count }, (_, i) => ({
      id: `img-${page}-${i}`,
      name: `p${page}-${i}.jpg`,
      path: `/p${page}-${i}.jpg`,
      size: 10,
      extension: 'jpg',
      modified: null,
      is_directory: false,
      metadata: {},
    })),
    total_count: more ? count * 10 : count,
    page,
    has_next: more,
  })
}

describe('collectImageIds', () => {
  it('reports truncation when the cap stops the walk before the last page', async () => {
    // "Run OCR on all pictures" that silently covers the first N is the defect:
    // the server is only handed the ids it was given, so it reports no
    // truncation of its own and the pictures past the cap are never analysed.
    server.use(
      http.get(`/api/v1/cases/${CASE}/files`, ({ request }) => {
        const page = Number(new URL(request.url).searchParams.get('page') ?? 1)
        return filesPage(page, 2, true)
      }),
    )

    const result = await collectImageIds(CASE, 'all', {}, 3)
    expect(result.ids).toHaveLength(3)
    expect(result.truncated).toBe(true)
  })

  it('reports no truncation when the selection ended on its own', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE}/files`, () => filesPage(1, 2, false)),
    )

    const result = await collectImageIds(CASE, 'all', {}, 3)
    expect(result.ids).toHaveLength(2)
    expect(result.truncated).toBe(false)
  })
})

describe('listExifRecords', () => {
  it('flags a walk that ended short of the record count the case reports', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE}/records`, () =>
        HttpResponse.json({
          records: [{ id: 'e1', parent_id: 'img1', metadata: {} }],
          total: 90000,
        }),
      ),
    )

    const result = await listExifRecords(CASE)
    expect(result.records).toHaveLength(1)
    expect(result.truncated).toBe(true)
  })

  it('terminates on a short page instead of walking to the cap when the server states no total', async () => {
    // A response without a usable count must not spin: the walk stops on the
    // page itself. Counting the requests is the point — an unbounded walk here
    // is what made the overlay fetch tens of thousands of times.
    let requests = 0
    server.use(
      http.get(`/api/v1/cases/${CASE}/records`, () => {
        requests += 1
        return HttpResponse.json({
          records: [{ id: 'e1', parent_id: 'img1', metadata: {} }],
        })
      }),
    )

    const result = await listExifRecords(CASE)
    expect(requests).toBe(1)
    expect(result.records).toHaveLength(1)
    expect(result.truncated).toBe(false)
  })
})
