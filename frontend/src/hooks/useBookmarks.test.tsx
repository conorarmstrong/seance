import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook, waitFor } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import type { ReactNode } from 'react'
import { describe, expect, it } from 'vitest'
import type { BookmarkCategory } from '../api/types'
import { server } from '../test/server'
import { useBookmarks } from './useBookmarks'

const CASE = 'case-1'
const CATEGORIES: BookmarkCategory[] = [
  {
    id: 'cat-1',
    case_id: CASE,
    name: 'Key Evidence',
    color: '#e05c5c',
    created_at: 1700000000,
  },
]

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

function mockApi(ids: string[] = []) {
  const created: Record<string, unknown>[] = []
  server.use(
    http.get(`/api/v1/cases/${CASE}/bookmarks/ids`, () =>
      HttpResponse.json(ids),
    ),
    http.get(`/api/v1/cases/${CASE}/bookmarks/categories`, () =>
      HttpResponse.json(CATEGORIES),
    ),
    http.post(`/api/v1/cases/${CASE}/bookmarks`, async ({ request }) => {
      created.push((await request.json()) as Record<string, unknown>)
      return HttpResponse.json({ id: 'bm-new' })
    }),
    http.delete(`/api/v1/cases/${CASE}/bookmarks/:artifactId`, () =>
      HttpResponse.json({ success: true }),
    ),
  )
  return created
}

describe('useBookmarks', () => {
  it('reports an id it has not loaded yet as unknown, never as unmarked', async () => {
    mockApi(['art-1'])
    const { result } = renderHook(() => useBookmarks(CASE), { wrapper })

    // Before the ids arrive the honest answer is "we do not know". A `false`
    // here would paint every row with a hollow star, which an examiner reads
    // as "nothing in this list is bookmarked".
    expect(result.current.isBookmarked('art-1')).toBeNull()

    await waitFor(() =>
      expect(result.current.isBookmarked('art-1')).toBe(true),
    )
    expect(result.current.isBookmarked('art-2')).toBe(false)
  })

  it('sends the note and the category recorded at the moment of capture', async () => {
    const created = mockApi()
    const { result } = renderHook(() => useBookmarks(CASE), { wrapper })
    await waitFor(() => expect(result.current.idsLoaded).toBe(true))

    await act(async () => {
      await result.current.add('art-9', {
        categoryId: 'cat-1',
        note: 'matches CCTV entry time',
      })
    })

    expect(created).toEqual([
      {
        artifact_id: 'art-9',
        category_id: 'cat-1',
        note: 'matches CCTV entry time',
      },
    ])
  })

  it('omits an empty note rather than storing a blank one', async () => {
    const created = mockApi()
    const { result } = renderHook(() => useBookmarks(CASE), { wrapper })
    await waitFor(() => expect(result.current.idsLoaded).toBe(true))

    await act(async () => {
      await result.current.add('art-9', { note: '   ' })
    })

    expect(created).toEqual([{ artifact_id: 'art-9' }])
  })

  it('surfaces the categories a capture can be filed under', async () => {
    mockApi()
    const { result } = renderHook(() => useBookmarks(CASE), { wrapper })
    await waitFor(() => expect(result.current.categories).toHaveLength(1))
    expect(result.current.categories[0].name).toBe('Key Evidence')
  })

  it('reports a failed ids load rather than answering from an empty set', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE}/bookmarks/ids`, () =>
        HttpResponse.json({ error: 'boom' }, { status: 500 }),
      ),
      http.get(`/api/v1/cases/${CASE}/bookmarks/categories`, () =>
        HttpResponse.json(CATEGORIES),
      ),
    )
    const { result } = renderHook(() => useBookmarks(CASE), { wrapper })
    await waitFor(() => expect(result.current.idsError).not.toBeNull())
    expect(result.current.isBookmarked('art-1')).toBeNull()
    expect(result.current.idsLoaded).toBe(false)
  })
})
