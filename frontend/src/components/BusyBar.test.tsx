import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { BusyBar } from './BusyBar'

function renderWithQuery(children: React.ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      {children}
      <BusyBar />
    </QueryClientProvider>,
  )
}

function PendingQuery() {
  useQuery({
    queryKey: ['busybar-pending'],
    queryFn: () => new Promise(() => {}),
  })
  return null
}

function InstantQuery() {
  const query = useQuery({
    queryKey: ['busybar-instant'],
    queryFn: () => Promise.resolve('done'),
  })
  return <span>{query.data ?? 'waiting'}</span>
}

describe('BusyBar', () => {
  it('appears after 300ms while a query is in flight', () => {
    vi.useFakeTimers()
    try {
      renderWithQuery(<PendingQuery />)
      expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
      act(() => vi.advanceTimersByTime(250))
      expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
      act(() => vi.advanceTimersByTime(100))
      expect(screen.getByRole('progressbar')).toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })

  it('does not flash for fetches faster than the debounce', async () => {
    renderWithQuery(<InstantQuery />)
    await waitFor(() => expect(screen.getByText('done')).toBeInTheDocument())
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
    // Still absent after the debounce window has fully elapsed.
    await new Promise((r) => setTimeout(r, 350))
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
  })
})
