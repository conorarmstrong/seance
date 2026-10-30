import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  initialProcessingFor,
  type ProcessingState,
} from '../../hooks/processing'
import { ToastProvider } from '../toast/ToastProvider'
import { server } from '../../test/server'
import { ProcessingPanel } from './ProcessingPanel'

function makeState(overrides: Partial<ProcessingState>): ProcessingState {
  return { ...initialProcessingFor('case-1'), ...overrides }
}

function renderPanel(state: ProcessingState) {
  return render(
    <ToastProvider>
      <ProcessingPanel state={state} />
    </ToastProvider>,
  )
}

describe('ProcessingPanel collapse', () => {
  beforeEach(() => localStorage.clear())

  it('collapses the body while keeping the heading that says work is running', async () => {
    const user = userEvent.setup()
    renderPanel(
      makeState({ active: true, phase: 'Record Parsing', processed: 1234 }),
    )
    expect(screen.getByText(/1,234 artifacts/)).toBeVisible()

    await user.click(screen.getByRole('button', { name: /Record Parsing/ }))

    // The detail goes; the claim that a run is live, and which phase it is in,
    // does not. Collapsing must never make a running case look idle.
    expect(screen.queryByText(/1,234 artifacts/)).not.toBeVisible()
    expect(screen.getByText(/Processing — Record Parsing/)).toBeVisible()
  })

  it('remembers the choice for the next run rather than the current one', async () => {
    const user = userEvent.setup()
    const first = renderPanel(makeState({ active: true, phase: 'Extract' }))
    await user.click(screen.getByRole('button', { name: /Extract/ }))
    first.unmount()

    // A different case and a different run: the preference is about this
    // examiner's screen, so it survives both.
    renderPanel({
      ...makeState({ active: true, phase: 'Carving' }),
      caseId: 'case-2',
    })
    expect(screen.getByRole('button', { name: /Carving/ })).toHaveAttribute(
      'aria-expanded',
      'false',
    )
  })

  it('opens when storage cannot be read, rather than hiding the run', () => {
    const getItem = vi
      .spyOn(Storage.prototype, 'getItem')
      .mockImplementation(() => {
        throw new Error('site data blocked')
      })
    try {
      renderPanel(makeState({ active: true, phase: 'Extract', processed: 7 }))
      expect(screen.getByText(/7 artifacts/)).toBeVisible()
    } finally {
      getItem.mockRestore()
    }
  })
})

describe('ProcessingPanel', () => {
  it('renders nothing while idle', () => {
    const { container } = renderPanel(makeState({}))
    expect(container.querySelector('.processing-panel')).toBeNull()
  })

  it('shows the phase task bar when tasks_total is known', () => {
    renderPanel(
      makeState({
        active: true,
        phase: 'Extract',
        processed: 42,
        tasksCompleted: 3,
        tasksTotal: 10,
      }),
    )
    expect(screen.getByText('Processing — Extract')).toBeInTheDocument()
    expect(screen.getByText('3 / 10 tasks (30%)')).toBeInTheDocument()
  })

  it('never rounds an unfinished run up to 100%', () => {
    // UI-002: 148,215 of 148,216 rounds to 100 and reads as finished while a
    // task is still outstanding. 100 must mean done.
    renderPanel(
      makeState({
        active: true,
        phase: 'Extract',
        processed: 148_215,
        tasksCompleted: 148_215,
        tasksTotal: 148_216,
      }),
    )
    expect(
      screen.getByText('148,215 / 148,216 tasks (99%)'),
    ).toBeInTheDocument()
  })

  it('never rounds a run that has done nothing up off 0%', () => {
    // The other end of the same rule: a run with no work done must not claim
    // 1% of progress it has not made.
    renderPanel(
      makeState({
        active: true,
        phase: 'Extract',
        processed: 0,
        tasksCompleted: 0,
        tasksTotal: 200,
      }),
    )
    expect(screen.getByText('0 / 200 tasks (0%)')).toBeInTheDocument()
  })

  it('shows an indeterminate bar while discovering, then a real percentage', () => {
    const { container, rerender } = renderPanel(
      makeState({
        active: true,
        phase: 'Extract',
        discovering: true,
        tasksCompleted: 2,
        tasksTotal: 40,
      }),
    )
    expect(screen.getByText('Discovering tasks…')).toBeInTheDocument()
    expect(container.querySelector('.processing-tasks .indeterminate')).not.toBeNull()
    expect(screen.queryByText(/tasks \(/)).toBeNull()

    // Discovery finishes: switch to a determinate percentage bar.
    rerender(
      <ToastProvider>
        <ProcessingPanel
          state={makeState({
            active: true,
            phase: 'Extract',
            discovering: false,
            tasksCompleted: 20,
            tasksTotal: 40,
          })}
        />
      </ToastProvider>,
    )
    expect(screen.queryByText('Discovering tasks…')).toBeNull()
    expect(screen.getByText('20 / 40 tasks (50%)')).toBeInTheDocument()
    expect(container.querySelector('.processing-tasks .indeterminate')).toBeNull()
  })

  it('renders eta and throughput, and just the rate while discovering', () => {
    const { rerender } = renderPanel(
      makeState({ active: true, ratePerSec: 1540, etaSeconds: 130 }),
    )
    expect(
      screen.getByText('~2m 10s remaining · 1,540 artifacts/sec'),
    ).toBeInTheDocument()

    rerender(
      <ToastProvider>
        <ProcessingPanel
          state={makeState({
            active: true,
            discovering: true,
            ratePerSec: 1540,
            etaSeconds: null,
          })}
        />
      </ToastProvider>,
    )
    expect(screen.getByText('1,540 artifacts/sec')).toBeInTheDocument()
    expect(screen.queryByText(/remaining/)).toBeNull()
  })

  it('shows the humanized active-module label', () => {
    renderPanel(
      makeState({
        active: true,
        activeModules: ['plugin.ntfs.mft_parser', 'plugin.search.indexer'],
      }),
    )
    expect(
      screen.getByText('NTFS MFT parser · Search index'),
    ).toBeInTheDocument()
  })

  it('renders an MFT module line with humanized name and record counts', () => {
    renderPanel(
      makeState({
        active: true,
        modules: {
          'plugin.ntfs.mft_parser:art-1': {
            moduleId: 'plugin.ntfs.mft_parser',
            artifactId: 'art-1',
            unitsDone: 45000,
            unitsTotal: 82000,
            unit: 'records',
            updatedAt: Date.now(),
          },
        },
      }),
    )
    expect(screen.getByText('NTFS MFT parser')).toBeInTheDocument()
    expect(screen.getByText('45,000 of 82,000 records')).toBeInTheDocument()
  })

  it('displays the smoothed live count ahead of the last snapshot', () => {
    renderPanel(makeState({ active: true, processed: 100, liveCount: 165 }))
    expect(screen.getByText('165 artifacts')).toBeInTheDocument()
  })

  it('renders module lines with byte progress, shimmer, and staleness', () => {
    const now = Date.now()
    renderPanel(
      makeState({
        active: true,
        modules: {
          'mft:art-1': {
            moduleId: 'mft',
            artifactId: 'art-1',
            unitsDone: 512,
            unitsTotal: 1024,
            unit: 'bytes',
            updatedAt: now,
          },
          'registry:art-2': {
            moduleId: 'registry',
            artifactId: 'art-2',
            unitsDone: 7,
            unitsTotal: null,
            unit: 'items',
            updatedAt: now - 90_000, // stale but not dropped
          },
        },
      }),
    )
    expect(screen.getByText('mft')).toBeInTheDocument()
    expect(screen.getByText('512 B of 1.0 KiB')).toBeInTheDocument()
    const staleLine = screen.getByText('registry').closest('.processing-module-line')
    expect(staleLine).toHaveClass('stale')
    expect(staleLine?.querySelector('.indeterminate')).not.toBeNull()
  })

  it('caps the module lane at five lines', () => {
    const now = Date.now()
    const modules: ProcessingState['modules'] = {}
    for (let i = 0; i < 8; i++) {
      modules[`mod-${i}:a`] = {
        moduleId: `mod-${i}`,
        artifactId: 'a',
        unitsDone: i,
        unitsTotal: null,
        unit: 'items',
        updatedAt: now - i,
      }
    }
    const { container } = renderPanel(makeState({ active: true, modules }))
    expect(container.querySelectorAll('.processing-module-line')).toHaveLength(5)
  })

  it('shows the acquisition hashing line', () => {
    renderPanel(
      makeState({
        hashing: {
          '/evidence/disk.dd': {
            source: '/evidence/disk.dd',
            bytesDone: 100,
            bytesTotal: 400,
            updatedAt: Date.now(),
          },
        },
      }),
    )
    expect(screen.getByText('Acquiring evidence')).toBeInTheDocument()
    expect(
      screen.getByText('Hashing disk.dd — 100 B of 400 B (25%)'),
    ).toBeInTheDocument()
  })

  it('shows the reconnecting chip', () => {
    renderPanel(
      makeState({ active: true, connectionState: 'reconnecting' }),
    )
    expect(screen.getByText('reconnecting…')).toBeInTheDocument()
  })

  it('cancels processing after an inline confirm', async () => {
    let cancelCalled = false
    server.use(
      http.post('/api/v1/cases/case-1/processing/cancel', () => {
        cancelCalled = true
        return HttpResponse.json({ cancelling: true })
      }),
    )
    const user = userEvent.setup()
    const { rerender } = renderPanel(makeState({ active: true, phase: 'Extract' }))

    await user.click(screen.getByRole('button', { name: 'Cancel processing' }))
    expect(
      screen.getByText('Stop processing? Already-extracted artifacts are kept.'),
    ).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Stop' }))
    const cancelling = screen.getByRole('button', { name: 'Cancelling…' })
    expect(cancelling).toBeDisabled()
    await waitFor(() => expect(cancelCalled).toBe(true))

    // processing_cancelled arrives over SSE.
    rerender(
      <ToastProvider>
        <ProcessingPanel
          state={makeState({
            active: false,
            cancelled: true,
            cancelledArtifacts: 12,
          })}
        />
      </ToastProvider>,
    )
    expect(screen.getByText('Processing cancelled')).toBeInTheDocument()
    expect(
      screen.getByText('Cancelled — 12 artifacts processed'),
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Cancelling…' })).toBeNull()
  })

  it('does not print zero when the cancel carried no artifact count', () => {
    // `?? 0` turned "the run stopped and we were not told how much it did" into
    // "the run stopped having produced nothing" — an affirmative claim about
    // the evidence, made up by the UI.
    renderPanel(
      makeState({ active: false, cancelled: true, cancelledArtifacts: null }),
    )
    expect(
      screen.getByText('Cancelled — artifacts processed not reported'),
    ).toBeInTheDocument()
    expect(screen.queryByText(/Cancelled — 0 artifacts/)).toBeNull()
  })

  it('closes an open cancel confirmation when the case changes', async () => {
    // The panel lives in the sidebar and stays mounted across a `:caseId`
    // change. An open "Stop processing?" opened over case 1 would otherwise be
    // confirmed against case 2 — cancelling an acquisition nobody asked to
    // stop, with the chrome still describing the other case's run.
    const cancelled: string[] = []
    server.use(
      http.post('/api/v1/cases/:caseId/processing/cancel', ({ params }) => {
        cancelled.push(params.caseId as string)
        return HttpResponse.json({ cancelling: true })
      }),
    )
    const user = userEvent.setup()
    const { rerender } = renderPanel(makeState({ active: true }))
    await user.click(screen.getByRole('button', { name: 'Cancel processing' }))
    expect(
      screen.getByText('Stop processing? Already-extracted artifacts are kept.'),
    ).toBeInTheDocument()

    rerender(
      <ToastProvider>
        <ProcessingPanel
          state={{ ...initialProcessingFor('case-2'), active: true }}
        />
      </ToastProvider>,
    )

    expect(
      screen.queryByText(
        'Stop processing? Already-extracted artifacts are kept.',
      ),
    ).toBeNull()
    expect(screen.queryByRole('button', { name: 'Stop' })).toBeNull()
    expect(cancelled).toEqual([])
  })

  it('keeps running when the confirm is declined', async () => {
    const user = userEvent.setup()
    renderPanel(makeState({ active: true }))
    await user.click(screen.getByRole('button', { name: 'Cancel processing' }))
    await user.click(screen.getByRole('button', { name: 'Keep running' }))
    expect(
      screen.getByRole('button', { name: 'Cancel processing' }),
    ).toBeEnabled()
  })

  it('re-enables the cancel button when the request fails', async () => {
    server.use(
      http.post('/api/v1/cases/case-1/processing/cancel', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'boom' } },
          { status: 500 },
        ),
      ),
    )
    const user = userEvent.setup()
    renderPanel(makeState({ active: true }))
    await user.click(screen.getByRole('button', { name: 'Cancel processing' }))
    await user.click(screen.getByRole('button', { name: 'Stop' }))
    expect(await screen.findByText('Cancel request failed')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Cancel processing' }),
    ).toBeEnabled()
  })

  it('dismisses a completed panel and re-shows it on a new run', async () => {
    const { container, rerender } = renderPanel(
      makeState({ complete: true, totalArtifacts: 1234, durationMs: 5000 }),
    )
    // The finished panel carries a dismiss (X) control.
    expect(screen.getByText('Processing complete')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(container.querySelector('.processing-panel')).toBeNull()

    // A new run clears the dismissal so the next result shows again...
    rerender(
      <ToastProvider>
        <ProcessingPanel state={makeState({ active: true, phase: 'Extract' })} />
      </ToastProvider>,
    )
    expect(await screen.findByText('Processing — Extract')).toBeInTheDocument()
    // ...and an in-progress run has no dismiss control (it has Cancel instead).
    expect(screen.queryByRole('button', { name: 'Dismiss' })).toBeNull()
    expect(
      screen.getByRole('button', { name: 'Cancel processing' }),
    ).toBeInTheDocument()
  })
})

/**
 * Every figure in this panel comes from an event, and the stream that carries
 * them has no replay. When it goes down — or when a run stops being talked
 * about over a socket that is still up — the panel is looking at a photograph,
 * and it has to say so rather than presenting it as a live view.
 */
describe('ProcessingPanel when the run can no longer be vouched for', () => {
  const NOW = Date.now()

  it('marks the figures as unconfirmed while the stream is down', () => {
    renderPanel(
      makeState({
        active: true,
        phase: 'Extract',
        processed: 1204331,
        liveCount: 1204331,
        connectionState: 'reconnecting',
        streamDownSince: NOW - 30_000,
        lastEventAt: NOW - 32_000,
      }),
    )
    expect(screen.getByText('reconnecting…')).toBeInTheDocument()
    expect(
      screen.getByText(/run state unknown — event stream down since/),
    ).toBeInTheDocument()
    // The count is still shown — it is the last thing that was true — but it is
    // dated, so nobody reads it as the state of the run right now.
    expect(screen.getByText(/last confirmed .* UTC/)).toBeInTheDocument()
  })

  it('reports a run whose completion never arrived, and refuses to call it complete', () => {
    // The panel used to render nothing at all in this state: not active, not
    // complete, not cancelled. The one thing the examiner needed to know — that
    // the run finished while nobody was listening, so the totals on the case
    // pages are the ones to trust — had no home.
    renderPanel(
      makeState({
        endedUnobserved: true,
        processed: 1204331,
        lastEventAt: NOW - 600_000,
      }),
    )
    expect(
      screen.getByText('Run ended — completion not received'),
    ).toBeInTheDocument()
    expect(screen.queryByText('Processing complete')).not.toBeInTheDocument()
    expect(
      screen.getByText(/1,204,331 artifacts — the last count heard, not a final total/),
    ).toBeInTheDocument()
  })

  it('never renders two totals for one run, whatever state it is handed', () => {
    // The state below is the one the sticky flag used to produce: a completion
    // event that arrived after reconciliation had already inferred an ending.
    // The reducer can no longer build it — every terminal transition goes
    // through one constructor — but a snapshot written by an older build,
    // restored inside a tab session that outlived a deploy, still can. The
    // panel therefore picks ONE ending and renders ONE figure, and the one it
    // picks is the event it actually heard.
    const { container } = renderPanel(
      makeState({
        complete: true,
        totalArtifacts: 412806,
        durationMs: 41_200,
        endedUnobserved: true,
        processed: 389204,
        lastEventAt: NOW - 600_000,
      }),
    )
    expect(container.querySelectorAll('.processing-count')).toHaveLength(1)
    expect(screen.getByText(/412,806 artifacts · 41\.2s/)).toBeInTheDocument()
    expect(screen.queryByText(/389,204/)).not.toBeInTheDocument()
    expect(
      screen.queryByText('Run ended — completion not received'),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByText(/No completion event for this run ever reached/),
    ).not.toBeInTheDocument()
    expect(screen.getByText('Processing complete')).toBeInTheDocument()
  })

  it('says how many errors are counted but not listed before the cap ever bites', () => {
    // A damaged image throws 74 module errors — well under the 200 the state
    // retains, so nothing was dropped and the "counted but not listed" note
    // stayed silent. The examiner expanded "74 module errors", read ten lines,
    // and had nothing on screen saying the other 64 existed. The band the note
    // used to cover (past 200) is the rare one; this is the common one.
    renderPanel(
      makeState({
        active: true,
        phase: 'Extract',
        lastEventAt: NOW,
        errors: Array.from({ length: 74 }, (_, i) => ({
          case_id: 'case-1',
          module_id: `plugin.m${i}`,
          artifact_id: `art-${i}`,
          error: 'boom',
        })),
      }),
    )
    expect(screen.getByText('74 module errors')).toBeInTheDocument()
    expect(
      screen.getByText(
        /showing the most recent 10 · 64 earlier errors are counted but not listed/,
      ),
    ).toBeInTheDocument()
  })

  it('says nothing about a list that is complete', () => {
    renderPanel(
      makeState({
        active: true,
        phase: 'Extract',
        lastEventAt: NOW,
        errors: Array.from({ length: 3 }, (_, i) => ({
          case_id: 'case-1',
          module_id: `plugin.m${i}`,
          artifact_id: `art-${i}`,
          error: 'boom',
        })),
      }),
    )
    expect(screen.getByText('3 module errors')).toBeInTheDocument()
    expect(screen.queryByText(/counted but not listed/)).not.toBeInTheDocument()
  })

  it('counts module errors that the bounded list no longer holds', () => {
    renderPanel(
      makeState({
        active: true,
        phase: 'Extract',
        lastEventAt: NOW,
        errors: [
          {
            case_id: 'case-1',
            module_id: 'plugin.x',
            artifact_id: 'a',
            error: 'boom',
          },
        ],
        errorsDropped: 4_999,
      }),
    )
    expect(screen.getByText('5,000 module errors')).toBeInTheDocument()
    expect(
      screen.getByText(/showing the most recent 1 · 4,999 earlier errors are counted but not listed/),
    ).toBeInTheDocument()
  })
})
