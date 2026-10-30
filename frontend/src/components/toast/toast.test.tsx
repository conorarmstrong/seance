import { act, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ToastProvider, useToast } from './ToastProvider'

function Trigger({ kind }: { kind: 'info' | 'success' | 'error' }) {
  const toast = useToast()
  return (
    <button onClick={() => toast[kind](`${kind} message`)}>fire</button>
  )
}

describe('toast system', () => {
  it('shows a toast when fired', async () => {
    render(
      <ToastProvider>
        <Trigger kind="success" />
      </ToastProvider>,
    )
    act(() => screen.getByText('fire').click())
    expect(await screen.findByText('success message')).toBeInTheDocument()
    expect(screen.getByRole('status')).toBeInTheDocument()
  })

  it('auto-dismisses after the timeout', async () => {
    vi.useFakeTimers()
    try {
      render(
        <ToastProvider>
          <Trigger kind="info" />
        </ToastProvider>,
      )
      act(() => screen.getByText('fire').click())
      expect(screen.getByText('info message')).toBeInTheDocument()
      act(() => vi.advanceTimersByTime(6000))
      expect(screen.queryByText('info message')).not.toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })

  it('error toasts use an alert role', () => {
    render(
      <ToastProvider>
        <Trigger kind="error" />
      </ToastProvider>,
    )
    act(() => screen.getByText('fire').click())
    expect(screen.getByRole('alert')).toHaveTextContent('error message')
  })

  it('can be dismissed manually', async () => {
    render(
      <ToastProvider>
        <Trigger kind="info" />
      </ToastProvider>,
    )
    act(() => screen.getByText('fire').click())
    expect(screen.getByText('info message')).toBeInTheDocument()
    act(() =>
      screen.getByRole('button', { name: 'Dismiss notification' }).click(),
    )
    expect(screen.queryByText('info message')).not.toBeInTheDocument()
  })

  it('error toasts persist for 10 seconds', () => {
    vi.useFakeTimers()
    try {
      render(
        <ToastProvider>
          <Trigger kind="error" />
        </ToastProvider>,
      )
      act(() => screen.getByText('fire').click())
      act(() => vi.advanceTimersByTime(6000))
      expect(screen.getByText('error message')).toBeInTheDocument()
      act(() => vi.advanceTimersByTime(5000))
      expect(screen.queryByText('error message')).not.toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })

  it('dedupes identical consecutive messages within 2s and refreshes the timer', () => {
    vi.useFakeTimers()
    try {
      render(
        <ToastProvider>
          <Trigger kind="info" />
        </ToastProvider>,
      )
      act(() => screen.getByText('fire').click())
      act(() => vi.advanceTimersByTime(1000))
      act(() => screen.getByText('fire').click())
      // Only a single toast, not two stacked copies.
      expect(screen.getAllByText('info message')).toHaveLength(1)
      // Timer was refreshed: still visible 4.5s after the first push.
      act(() => vi.advanceTimersByTime(4500))
      expect(screen.getByText('info message')).toBeInTheDocument()
      act(() => vi.advanceTimersByTime(1000))
      expect(screen.queryByText('info message')).not.toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })

  it('shows at most 5 toasts, dropping the oldest', () => {
    function Numbered() {
      const toast = useToast()
      let n = 0
      return (
        <button
          onClick={() => {
            for (n = 0; n < 6; n++) toast.info(`message ${n}`)
          }}
        >
          fire-many
        </button>
      )
    }
    render(
      <ToastProvider>
        <Numbered />
      </ToastProvider>,
    )
    act(() => screen.getByText('fire-many').click())
    expect(screen.queryByText('message 0')).not.toBeInTheDocument()
    expect(screen.getByText('message 1')).toBeInTheDocument()
    expect(screen.getByText('message 5')).toBeInTheDocument()
    expect(screen.getAllByRole('status')).toHaveLength(5)
  })
})
