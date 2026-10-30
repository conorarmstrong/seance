import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import type { HashSetInfo } from '../../api/types'
import { server } from '../../test/server'
import { buildHashHitIndex, getHashHits, type HashHit } from './hashHits'

function set(id: string, set_type: string): HashSetInfo {
  return {
    id,
    case_id: 'c',
    name: `${id}-name`,
    description: null,
    set_type,
    hash_algorithm: 'sha256',
    entry_count: 1,
    imported_at: 0,
  }
}

function hit(artifact_id: string, hash_set_id: string): HashHit {
  return { artifact_id, hash_set_id, hash_set_name: `${hash_set_id}-name` }
}

describe('buildHashHitIndex', () => {
  it('classifies hits as notable or known by their set type', () => {
    const sets = [set('s-bad', 'notable'), set('s-good', 'known')]
    const index = buildHashHitIndex([hit('a', 's-bad'), hit('b', 's-good')], sets)
    expect(index.get('a')?.notable).toBe(true)
    expect(index.get('b')?.notable).toBe(false)
    expect(index.has('c')).toBe(false)
  })

  it('lets a notable match win when an artifact hits both notable and known sets', () => {
    const sets = [set('s-bad', 'notable'), set('s-good', 'known')]
    // known first, then notable — notable must still win.
    const index = buildHashHitIndex([hit('a', 's-good'), hit('a', 's-bad')], sets)
    expect(index.get('a')?.notable).toBe(true)
  })

  it('treats a hit against an unknown set as not notable', () => {
    const index = buildHashHitIndex([hit('a', 's-missing')], [])
    expect(index.get('a')?.notable).toBe(false)
  })
})

/** The page size the walk asks for; a shorter page ends it. */
const PAGE = 500

describe('getHashHits', () => {
  it('reports truncation when the cap ended the walk and the server stated no total', async () => {
    // The defect: truncation judged only by comparing against `total`. A
    // response that omits the count then makes a result the cap cut short
    // report as complete, and every picture past the cap loses its
    // notable/known badge with nothing on screen saying the overlay stopped —
    // "not in any hash set" and "never checked" render identically.
    let requests = 0
    server.use(
      http.get('/api/v1/cases/c1/hash_hits', () => {
        requests += 1
        return HttpResponse.json({
          hits: Array.from({ length: PAGE }, (_, i) => ({
            artifact_id: `a-${requests}-${i}`,
            hash_set_id: 's1',
            hash_set_name: 'notable set',
          })),
        })
      }),
    )

    const result = await getHashHits('c1', PAGE * 2)
    expect(result.hits).toHaveLength(PAGE * 2)
    expect(result.truncated).toBe(true)
  })

  it('stops on a short page instead of walking to the cap, and calls that complete', async () => {
    // A page shorter than the one asked for is the server's own end-of-data
    // signal. Trusting `total` alone to stop the walk issues a request per page
    // all the way to the cap against a server that omits the count.
    let requests = 0
    server.use(
      http.get('/api/v1/cases/c1/hash_hits', () => {
        requests += 1
        return HttpResponse.json({
          hits: [
            { artifact_id: 'a1', hash_set_id: 's1', hash_set_name: 'set' },
          ],
        })
      }),
    )

    const result = await getHashHits('c1')
    expect(requests).toBe(1)
    expect(result.hits).toHaveLength(1)
    expect(result.truncated).toBe(false)
  })
})
