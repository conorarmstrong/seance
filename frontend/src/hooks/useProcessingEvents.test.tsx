import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook, screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ToastProvider } from '../components/toast/ToastProvider'
import { server } from '../test/server'
import {
  clearIngestTracking,
  initialProcessingFor,
  trackIngest,
  type ProcessingState,
} from './processing'
import { resetSseBus } from './sse'
import { useProcessingEvents } from './useProcessingEvents'

/** The server's answer to "is anything running?"; `active_tasks` is
 *  process-wide, which is exactly what the endpoint documents. */
function serverReports(activeTasks: number) {
  server.use(
    http.get('/api/v1/status', () =>
      HttpResponse.json({ active_tasks: activeTasks, scope: 'process' }),
    ),
  )
}

type Listener = (event: MessageEvent) => void

class MockEventSource {
  static instances: MockEventSource[] = []
  url: string
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  closed = false
  private listeners = new Map<string, Set<Listener>>()

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }

  addEventListener(name: string, listener: Listener) {
    if (!this.listeners.has(name)) this.listeners.set(name, new Set())
    this.listeners.get(name)!.add(listener)
  }

  removeEventListener(name: string, listener: Listener) {
    this.listeners.get(name)?.delete(listener)
  }

  close() {
    this.closed = true
  }

  open() {
    this.onopen?.()
  }

  fail() {
    this.onerror?.()
  }

  emit(name: string, payload: unknown) {
    // Real EventSource stamps the named-event type onto the MessageEvent;
    // useProcessingEvents keys off it for the bare artifact_batch payload.
    const event = { data: JSON.stringify(payload), type: name } as MessageEvent
    for (const listener of this.listeners.get(name) ?? []) listener(event)
  }
}

function wrapper({ children }: { children: ReactNode }) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>{children}</ToastProvider>
    </QueryClientProvider>
  )
}

const latest = () =>
  MockEventSource.instances[MockEventSource.instances.length - 1]

beforeEach(() => {
  sessionStorage.clear()
  MockEventSource.instances = []
  vi.stubGlobal('EventSource', MockEventSource)
  vi.useFakeTimers()
  // The stream is shared process-wide, so it outlives a single test unless it
  // is torn down with the stubbed EventSource that backs it.
  resetSseBus()
  // Reconciliation asks the server whether anything is still running whenever
  // this client has reason to doubt its own picture. "Something is running"
  // is the answer that changes nothing, so it is the default here; the tests
  // that care override it.
  serverReports(1)
})

afterEach(() => {
  resetSseBus()
  vi.useRealTimers()
  vi.unstubAllGlobals()
  clearIngestTracking('case-1')
})

describe('useProcessingEvents', () => {
  it('starts live and applies processing_status events for this case', () => {
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    expect(result.current.connectionState).toBe('live')

    act(() => {
      latest().open()
      latest().emit('processing_status', {
        event_type: 'PhaseStarted',
        case_id: 'case-1',
        phase: 'Extract',
        artifact_type: 'x',
      })
      latest().emit('processing_status', {
        event_type: 'PhaseStarted',
        case_id: 'case-2',
        phase: 'Other',
        artifact_type: 'x',
      })
    })
    expect(result.current.active).toBe(true)
    expect(result.current.phase).toBe('Extract')
  })

  it('reconnects with increasing backoff and resets transient progress', () => {
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    act(() => {
      latest().open()
      latest().emit('processing_status', {
        event_type: 'PhaseStarted',
        case_id: 'case-1',
        phase: 'Extract',
        artifact_type: 'x',
      })
      latest().emit('module_progress', {
        event_type: 'ModuleProgress',
        module_id: 'mft',
        artifact_id: 'art-1',
        units_done: 1,
        units_total: null,
        unit: 'items',
      })
    })
    expect(Object.keys(result.current.modules)).toHaveLength(1)
    expect(MockEventSource.instances).toHaveLength(1)

    // First drop: reconnecting, retry after 1s.
    act(() => latest().fail())
    expect(result.current.connectionState).toBe('reconnecting')
    expect(MockEventSource.instances).toHaveLength(1)
    act(() => vi.advanceTimersByTime(999))
    expect(MockEventSource.instances).toHaveLength(1)
    act(() => vi.advanceTimersByTime(1))
    expect(MockEventSource.instances).toHaveLength(2)

    // Second consecutive failure backs off to 2s.
    act(() => latest().fail())
    act(() => vi.advanceTimersByTime(1999))
    expect(MockEventSource.instances).toHaveLength(2)
    act(() => vi.advanceTimersByTime(1))
    expect(MockEventSource.instances).toHaveLength(3)

    // Reconnect goes live again and clears transient lanes.
    act(() => latest().open())
    expect(result.current.connectionState).toBe('live')
    expect(result.current.modules).toEqual({})
    expect(result.current.active).toBe(true)
  })

  it('caps the backoff at 10s', () => {
    renderHook(() => useProcessingEvents('case-1'), { wrapper })
    act(() => latest().open())
    for (let i = 0; i < 6; i++) {
      act(() => latest().fail())
      act(() => vi.advanceTimersByTime(10_000))
    }
    // 1s, 2s, 5s then 10s each; every failure still reconnects.
    expect(MockEventSource.instances).toHaveLength(7)
  })

  it('invalidates stale query roots and toasts on ProcessingComplete', () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper: ({ children }: { children: ReactNode }) => (
        <QueryClientProvider client={queryClient}>
          <ToastProvider>{children}</ToastProvider>
        </QueryClientProvider>
      ),
    })
    act(() => {
      latest().open()
      latest().emit('processing_status', {
        event_type: 'ProcessingComplete',
        case_id: 'case-1',
        total_artifacts: 250,
        total_duration_ms: 9000,
        artifacts_by_type: [['FileEntry', 250]],
      })
    })
    expect(result.current.complete).toBe(true)
    // Invalidation is now a single predicate matching every case-scoped query,
    // so a finished run refreshes all views (not a hand-maintained root subset).
    const predicate = invalidate.mock.calls
      .map((c) => c[0]?.predicate)
      .find((p): p is (q: { queryKey: unknown }) => boolean => typeof p === 'function')
    expect(predicate).toBeTypeOf('function')
    // Matches any query key mentioning this case...
    for (const key of [
      ['case', 'case-1'],
      ['gallery-images', 'case-1'],
      ['system-info', 'case-1'],
      ['comms', 'case-1'],
      ['timeline-histogram', 'case-1'],
    ]) {
      expect(predicate!({ queryKey: key })).toBe(true)
    }
    // ...but not other cases or the case-list.
    expect(predicate!({ queryKey: ['gallery-images', 'other-case'] })).toBe(false)
    expect(predicate!({ queryKey: ['cases'] })).toBe(false)
    expect(
      screen.getByText('Processing complete — 250 artifacts'),
    ).toBeInTheDocument()
  })

  it('toasts on cancellation and tracked ingest failure', () => {
    trackIngest('case-1', { artifactId: 'art-9', source: '/e/disk.dd' })
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    act(() => {
      latest().open()
      latest().emit('processing_status', {
        event_type: 'PhaseStarted',
        case_id: 'case-1',
        phase: 'Extract',
        artifact_type: 'x',
      })
    })
    act(() => {
      latest().emit('processing_cancelled', {
        event_type: 'ProcessingCancelled',
        artifacts_processed: 12,
      })
    })
    expect(result.current.cancelled).toBe(true)
    expect(
      screen.getByText('Processing cancelled — 12 artifacts processed'),
    ).toBeInTheDocument()

    act(() => {
      latest().emit('ingest_failed', {
        event_type: 'IngestFailed',
        artifact_id: 'art-9',
        error: 'disk unreadable',
      })
      latest().emit('ingest_failed', {
        event_type: 'IngestFailed',
        artifact_id: 'someone-elses',
        error: 'not ours',
      })
    })
    expect(
      screen.getByText('Ingest failed: disk unreadable'),
    ).toBeInTheDocument()
    expect(screen.queryByText('Ingest failed: not ours')).toBeNull()
  })

  it('ignores another case s cancellation instead of announcing this run stopped (B3-054)', () => {
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    act(() => {
      latest().open()
      latest().emit('processing_status', {
        event_type: 'PhaseStarted',
        case_id: 'case-1',
        phase: 'Extract',
        artifact_type: 'x',
      })
    })
    expect(result.current.active).toBe(true)

    // The SSE stream is global. Case 2 being cancelled says nothing about the
    // run the examiner is watching — and the reducer already drops it, so a
    // toast here would claim a stop that never happened while the panel keeps
    // showing progress. An examiner who believes it stops monitoring a live
    // acquisition.
    act(() => {
      latest().emit('processing_cancelled', {
        event_type: 'ProcessingCancelled',
        case_id: 'case-2',
        artifacts_processed: 12,
      })
    })

    expect(
      screen.queryByText('Processing cancelled — 12 artifacts processed'),
    ).toBeNull()
    expect(result.current.cancelled).toBe(false)
    expect(result.current.active).toBe(true)
  })

  it('advances the live count on artifact_batch and reconciles on PhaseProgress', () => {
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    act(() => {
      latest().open()
      latest().emit('processing_status', {
        event_type: 'PhaseStarted',
        case_id: 'case-1',
        phase: 'Extract',
        artifact_type: 'x',
      })
      latest().emit('processing_status', {
        event_type: 'PhaseProgress',
        case_id: 'case-1',
        artifacts_processed: 100,
        artifacts_by_type: [['FileEntry', 100]],
      })
    })
    expect(result.current.liveCount).toBe(100)

    // Two batches tick the count up between snapshots. A batch with no case_id
    // is a legacy server and keeps the previous behaviour.
    act(() => {
      latest().emit('artifact_batch', { case_id: 'case-1', count: 40 })
      latest().emit('artifact_batch', { count: 25 })
    })
    expect(result.current.liveCount).toBe(165)
    expect(result.current.processed).toBe(100)

    // The next authoritative snapshot reconciles the smoothed count.
    act(() => {
      latest().emit('processing_status', {
        event_type: 'PhaseProgress',
        case_id: 'case-1',
        artifacts_processed: 170,
        artifacts_by_type: [['FileEntry', 170]],
      })
    })
    expect(result.current.liveCount).toBe(170)
  })

  it('ignores an artifact_batch produced for another case (B2-043)', () => {
    // One SSE stream carries every case the viewer may see (an admin, or the
    // single-user default). Counting another case's batches against the open
    // case inflated its live count and the ETA derived from it, so the panel
    // reported progress that never happened for the case on screen.
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    act(() => {
      latest().open()
      latest().emit('processing_status', {
        event_type: 'PhaseStarted',
        case_id: 'case-1',
        phase: 'Extract',
        artifact_type: 'x',
      })
      latest().emit('processing_status', {
        event_type: 'PhaseProgress',
        case_id: 'case-1',
        artifacts_processed: 100,
        artifacts_by_type: [['FileEntry', 100]],
      })
    })
    expect(result.current.liveCount).toBe(100)

    act(() => {
      latest().emit('artifact_batch', { case_id: 'case-2', count: 5000 })
    })
    expect(result.current.liveCount).toBe(100)

    // The open case's own batch still counts.
    act(() => {
      latest().emit('artifact_batch', { case_id: 'case-1', count: 7 })
    })
    expect(result.current.liveCount).toBe(107)
  })

  it('resets state when the case changes without a remount', () => {
    const { result, rerender } = renderHook(
      ({ id }: { id: string }) => useProcessingEvents(id),
      { wrapper, initialProps: { id: 'case-1' } },
    )
    act(() => {
      latest().open()
      latest().emit('processing_status', {
        event_type: 'PhaseStarted',
        case_id: 'case-1',
        phase: 'Extract',
        artifact_type: 'x',
      })
    })
    expect(result.current.active).toBe(true)
    expect(result.current.caseId).toBe('case-1')

    // Switch to a different case in the same mounted shell.
    rerender({ id: 'case-2' })
    expect(result.current.caseId).toBe('case-2')
    expect(result.current.active).toBe(false)
    expect(result.current.phase).toBeNull()

    // Events for the new case now apply — they would have been dropped while
    // state.caseId was still pinned to case-1.
    act(() => {
      latest().open()
      latest().emit('processing_status', {
        event_type: 'PhaseStarted',
        case_id: 'case-2',
        phase: 'Carving',
        artifact_type: 'y',
      })
    })
    expect(result.current.active).toBe(true)
    expect(result.current.phase).toBe('Carving')
  })

  it('hydrates from a persisted snapshot and clears it on completion', () => {
    const first = renderHook(() => useProcessingEvents('case-1'), { wrapper })
    act(() => {
      latest().open()
      latest().emit('processing_status', {
        event_type: 'PhaseStarted',
        case_id: 'case-1',
        phase: 'Extract',
        artifact_type: 'x',
      })
    })
    first.unmount()

    // Fresh mount (simulated reload) restores the active phase.
    const second = renderHook(() => useProcessingEvents('case-1'), { wrapper })
    expect(second.result.current.active).toBe(true)
    expect(second.result.current.phase).toBe('Extract')

    act(() => {
      latest().open()
      latest().emit('processing_status', {
        event_type: 'ProcessingComplete',
        case_id: 'case-1',
        total_artifacts: 5,
        total_duration_ms: 100,
        artifacts_by_type: [],
      })
    })
    second.unmount()
    expect(sessionStorage.getItem('seance.processing.case-1')).toBeNull()

    const third = renderHook(() => useProcessingEvents('case-1'), { wrapper })
    expect(third.result.current.active).toBe(false)
    expect(third.result.current.phase).toBeNull()
  })
})

/**
 * The stream is a live broadcast with no replay. Anything sent while this
 * client was not listening is gone for good, and the terminal event is the one
 * that matters most: it is what ends the run in the UI and the ONLY trigger for
 * refreshing the case's queries. Missing it used to leave "processing" asserted
 * in the custody strip forever, every view frozen on pre-completion data, and
 * the Cancel button stuck on "Cancelling…" — with nothing on screen admitting
 * that the client had stopped hearing anything.
 */
describe('useProcessingEvents reconciliation after a gap', () => {
  const startRun = () => {
    act(() => {
      latest().open()
      latest().emit('processing_status', {
        event_type: 'PhaseStarted',
        case_id: 'case-1',
        phase: 'Extract',
        artifact_type: 'x',
      })
      latest().emit('processing_status', {
        event_type: 'PhaseProgress',
        case_id: 'case-1',
        artifacts_processed: 1204331,
        artifacts_by_type: [['FileEntry', 1204331]],
      })
    })
  }

  it('ends a run whose completion event was missed, and says how it learned', async () => {
    serverReports(0)
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper: ({ children }: { children: ReactNode }) => (
        <QueryClientProvider client={queryClient}>
          <ToastProvider>{children}</ToastProvider>
        </QueryClientProvider>
      ),
    })
    startRun()
    expect(result.current.active).toBe(true)

    // The lid closes. ProcessingComplete fires into a dead socket.
    act(() => latest().fail())
    expect(result.current.connectionState).toBe('reconnecting')
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000)
      latest().open()
      // The reconnect asks at once, but "nothing is running" is only conclusive
      // once it has outlived the interval the orchestrator broadcasts on, so
      // the answer is confirmed by a second reading before anything is
      // concluded from it (ZERO_TASKS_CONFIRM_MS).
      await vi.advanceTimersByTimeAsync(5_000)
    })

    expect(result.current.active).toBe(false)
    expect(result.current.endedUnobserved).toBe(true)
    // No completion event was seen, so there is no final total to report and
    // none is invented.
    expect(result.current.complete).toBe(false)
    expect(result.current.totalArtifacts).toBeNull()
    // The views behind the run have to be released too: the completion event
    // they were waiting on is never coming.
    expect(
      invalidate.mock.calls.some((c) => typeof c[0]?.predicate === 'function'),
    ).toBe(true)
    // ...and the snapshot that would have re-asserted the dead run on the next
    // reload is gone.
    expect(sessionStorage.getItem('seance.processing.case-1')).toBeNull()
  })

  it('does not declare a run over just because it lost the stream', async () => {
    // The endpoint counts queued and in-flight artifacts across every case this
    // process serves. A non-zero count cannot be attributed to this case, so it
    // proves nothing either way — and guessing here would end a live run on
    // screen while it is still writing artifacts to the case.
    serverReports(4)
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    startRun()

    act(() => latest().fail())
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000)
      latest().open()
      await vi.advanceTimersByTimeAsync(0)
    })

    expect(result.current.active).toBe(true)
    expect(result.current.endedUnobserved).toBe(false)
  })

  it('checks a run that has gone quiet on a healthy stream', async () => {
    // A server restart mid-run leaves the socket fine and the run gone.
    // PhaseProgress lands about every two seconds while a run is alive.
    serverReports(0)
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    startRun()
    expect(result.current.active).toBe(true)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(70_000)
    })

    expect(result.current.active).toBe(false)
    expect(result.current.endedUnobserved).toBe(true)
  })

  it('stops asserting a running run when the stream stays down for good', async () => {
    // The headline case: a laptop that slept leaves a half-open socket behind.
    // `onerror` fires, every retry dials into the dark, and because the socket
    // never opens again there is no generation bump and no reconnect-triggered
    // reconciliation — the path both other outage tests take. The only thing
    // left that can close the gap is the watchdog's stream-down branch, and it
    // has to do it long before the sixty seconds of silence would.
    serverReports(0)
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    startRun()
    expect(result.current.active).toBe(true)

    act(() => latest().fail())
    const dialled = MockEventSource.instances.length

    await act(async () => {
      await vi.advanceTimersByTimeAsync(25_000)
    })

    // Nothing ever came back up: the retries opened new sockets and none of
    // them reached `onopen`, so the client is still reconnecting.
    expect(MockEventSource.instances.length).toBeGreaterThan(dialled)
    expect(result.current.connectionState).toBe('reconnecting')
    // ...and this is well inside RUN_SILENT_MS, so only the stream-down branch
    // of the watchdog can have asked.
    expect(result.current.endedUnobserved).toBe(true)
    expect(result.current.active).toBe(false)
    expect(result.current.complete).toBe(false)
    expect(result.current.totalArtifacts).toBeNull()
  })

  it('does not end a run on a single zero reading taken inside the emit window', async () => {
    // `active_tasks` drops to zero the instant the last task finishes, but the
    // orchestrator only broadcasts the terminal event on its next two-second
    // tick. A reading taken in between is true and means nothing, so it is
    // confirmed before anything is concluded from it — and the event that
    // arrives during that wait is the answer, not the inference.
    serverReports(0)
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    startRun()

    // Sixty seconds of silence on a healthy socket brings the watchdog round.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(61_000)
    })
    expect(result.current.endedUnobserved).toBe(false)

    act(() => {
      latest().emit('processing_status', {
        event_type: 'ProcessingComplete',
        case_id: 'case-1',
        total_artifacts: 412806,
        total_duration_ms: 41_200,
        artifacts_by_type: [['FileEntry', 412806]],
      })
    })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000)
    })

    expect(result.current.complete).toBe(true)
    expect(result.current.totalArtifacts).toBe(412806)
    expect(result.current.endedUnobserved).toBe(false)
  })

  it('does not interrogate the server on a tab focus while the run is being talked about', async () => {
    // An examiner alt-tabs dozens of times an hour. Each return used to be an
    // unconditional `/status` probe over a perfectly live socket, and one of
    // them landing in the orchestrator's emit window was enough to declare a
    // healthy run ended. If this asked, the answer below would end the run.
    serverReports(0)
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    startRun()

    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await vi.advanceTimersByTimeAsync(5_000)
    })

    expect(result.current.active).toBe(true)
    expect(result.current.endedUnobserved).toBe(false)
  })

  it('re-reads the run from the server when the stream says it overran this client', async () => {
    // The broadcast dropped events this client never saw (HUNT-044). The
    // picture drawn from earlier events is not to be trusted, so the hook asks
    // the server — which here reports no run — rather than going on showing
    // the run it last heard about.
    serverReports(0)
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    startRun()
    expect(result.current.active).toBe(true)

    await act(async () => {
      latest().emit('lagged', { stream: 'status', skipped: 12 })
      await vi.advanceTimersByTimeAsync(5_000)
    })

    expect(result.current.endedUnobserved).toBe(true)
  })

  it('does ask on a tab focus once the run has gone unmentioned', async () => {
    serverReports(0)
    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    startRun()

    // Past the progress cadence but nowhere near the watchdog's sixty seconds
    // of silence, so only the visibility path can be asking.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(11_000)
    })
    expect(result.current.active).toBe(true)

    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'))
      await vi.advanceTimersByTimeAsync(5_000)
    })

    expect(result.current.endedUnobserved).toBe(true)
  })

  it('checks the server when it wakes up holding a snapshot from before the gap', async () => {
    // A snapshot restored from sessionStorage is a picture of the run as it was
    // when the tab was last alive. It used to be re-asserted as current for the
    // whole 15-minute TTL, count and phase and all, with no event ever arriving
    // to correct it.
    serverReports(0)
    const stale: ProcessingState = {
      ...initialProcessingFor('case-1'),
      active: true,
      phase: 'Extract',
      processed: 900,
    }
    sessionStorage.setItem(
      'seance.processing.case-1',
      JSON.stringify({ savedAt: Date.now() - 5 * 60_000, state: stale }),
    )

    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    expect(result.current.active).toBe(true)
    await act(async () => {
      // Long enough for the zero reading to be confirmed by a second one; see
      // ZERO_TASKS_CONFIRM_MS.
      await vi.advanceTimersByTimeAsync(5_000)
    })
    expect(result.current.active).toBe(false)
    expect(result.current.endedUnobserved).toBe(true)
  })
})

describe('the write-through snapshot stays cheap on a long run', () => {
  it('writes at most once a second, and always the newest state', () => {
    // Every artifact batch — two a second all run long — used to re-serialise
    // the entire state, including an error list with no upper bound, straight
    // into sessionStorage. On a damaged image that is an O(errors) write twice
    // a second until the quota rejects it and the reload protection the
    // snapshot exists for is silently switched off.
    const setItem = vi.spyOn(Storage.prototype, 'setItem')
    const writes = () =>
      setItem.mock.calls.filter((c) => c[0] === 'seance.processing.case-1')

    const { result } = renderHook(() => useProcessingEvents('case-1'), {
      wrapper,
    })
    act(() => {
      latest().open()
      latest().emit('processing_status', {
        event_type: 'PhaseStarted',
        case_id: 'case-1',
        phase: 'Extract',
        artifact_type: 'x',
      })
    })
    // The first write is immediate: a run that starts and a tab that reloads a
    // moment later must still restore.
    expect(writes()).toHaveLength(1)

    act(() => {
      for (let i = 1; i <= 20; i++) {
        latest().emit('artifact_batch', { case_id: 'case-1', count: 10 })
      }
    })
    expect(writes()).toHaveLength(1)

    act(() => vi.advanceTimersByTime(1000))
    expect(writes()).toHaveLength(2)
    // The write that lands is the state as it stands, not the one that was
    // pending when the throttle closed.
    const saved = JSON.parse(writes()[1][1] as string) as {
      state: ProcessingState
    }
    expect(saved.state.liveCount).toBe(result.current.liveCount)
    setItem.mockRestore()
  })
})
