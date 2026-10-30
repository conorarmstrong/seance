import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { describe, expect, it } from 'vitest'
import { useEntityScopedQuery } from './useEntityScopedQuery'

function wrapper() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

describe('useEntityScopedQuery', () => {
  it('reports data for the current scope as not stale', async () => {
    const { result } = renderHook(
      () =>
        useEntityScopedQuery<string>('case-1', {
          queryKey: ['rows', 'case-1'],
          queryFn: async () => 'case-1 rows',
        }),
      { wrapper: wrapper() },
    )

    await waitFor(() => expect(result.current.scoped).toBe('case-1 rows'))
    expect(result.current.stale).toBe(false)
  })

  it('flags a carried-over placeholder from the previous scope as stale', async () => {
    // The defect this guards (BUG-258): with `keepPreviousData`, switching the
    // entity hands back the PREVIOUS scope's rows while the new fetch is in
    // flight. If the scope tag is applied on read rather than at fetch time it
    // always matches the current scope, `stale` is never true, and the previous
    // case's evidence renders under the new case's heading.
    let release!: (v: string) => void
    const gate = new Promise<string>((r) => {
      release = r
    })

    const { result, rerender } = renderHook(
      ({ scope }: { scope: string }) =>
        useEntityScopedQuery<string>(scope, {
          queryKey: ['rows', scope],
          queryFn: () => (scope === 'case-1' ? Promise.resolve('case-1 rows') : gate),
        }),
      { wrapper: wrapper(), initialProps: { scope: 'case-1' } },
    )

    await waitFor(() => expect(result.current.scoped).toBe('case-1 rows'))

    // Switch entity; case-2's fetch has not resolved yet.
    rerender({ scope: 'case-2' })

    await waitFor(() => expect(result.current.stale).toBe(true))
    expect(result.current.scoped).toBeUndefined()
    // The raw value is still reachable for callers that want it, but `scoped`
    // (the one pages render) withholds it.
    expect(result.current.data).toBe('case-1 rows')

    release('case-2 rows')
    await waitFor(() => expect(result.current.scoped).toBe('case-2 rows'))
    expect(result.current.stale).toBe(false)
  })
})
