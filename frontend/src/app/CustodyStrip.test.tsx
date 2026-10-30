import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { initialProcessingFor, reduceProcessing } from '../hooks/processing'
import type { ProcessingState } from '../hooks/processing'
import { CustodyStrip } from './CustodyStrip'

const CASE = '11111111-1111-1111-1111-111111111111'

function strip(processing: ProcessingState) {
  render(
    <CustodyStrip examiner="A. Examiner" reference="REF-1" processing={processing} />,
  )
}

describe('CustodyStrip run state (B5-013)', () => {
  it('reports a cancelled run as cancelled, not as idle', () => {
    // The strip is always on screen and is what an examiner reads for run
    // state. Showing "idle" after a cancel put it in direct disagreement with
    // the processing panel, and hid that the case holds a partial result.
    const cancelled = reduceProcessing(
      { ...initialProcessingFor(CASE), active: true },
      {
        event_type: 'ProcessingCancelled',
        case_id: CASE,
        artifacts_processed: 42,
      },
    )
    strip(cancelled)
    expect(screen.getByText(/cancelled · 42 artifacts processed/)).toBeInTheDocument()
    expect(screen.queryByText(/^idle$/)).not.toBeInTheDocument()
  })

  it('still reads idle before anything has run', () => {
    strip(initialProcessingFor(CASE))
    expect(screen.getByText('idle')).toBeInTheDocument()
  })
})

/**
 * The strip is the one line an examiner glances at to know the case's state,
 * and it is on screen in every screenshot that ends up in a statement. So what
 * it says has to be something the client can actually stand behind: while the
 * event stream is down it has heard nothing, which is not the same fact as
 * nothing having happened.
 */
describe('CustodyStrip stream liveness', () => {
  const NOW = Date.now()

  it('will not report a case as idle while the stream is down', () => {
    strip({
      ...initialProcessingFor(CASE),
      connectionState: 'reconnecting',
      streamDownSince: NOW - 30_000,
    })
    expect(screen.queryByText('idle')).not.toBeInTheDocument()
    expect(
      screen.getByText(/run state unknown — event stream down since/),
    ).toBeInTheDocument()
  })

  it('stops asserting a running run once the stream carrying it has died', () => {
    strip({
      ...initialProcessingFor(CASE),
      active: true,
      processed: 1204331,
      lastEventAt: NOW - 40_000,
      connectionState: 'reconnecting',
      streamDownSince: NOW - 30_000,
    })
    // "processing · 1,204,331 artifacts" is exactly the line that gets quoted
    // as "analysis was still in progress at the time of review". It must not
    // outlive the connection that last confirmed it.
    expect(screen.queryByText(/processing · 1,204,331 artifacts/)).not.toBeInTheDocument()
    expect(screen.getByText(/run state unknown/)).toBeInTheDocument()
  })

  it('reports a run whose ending this client never heard', () => {
    strip({
      ...initialProcessingFor(CASE),
      processed: 1204331,
      endedUnobserved: true,
      lastEventAt: NOW - 600_000,
    })
    expect(
      screen.getByText(
        /run ended — no completion event received; final total not reported/,
      ),
    ).toBeInTheDocument()
  })

  it('reports the completion that arrived after reconciliation, not the gap before it', () => {
    // Reconciliation samples the server's in-flight count, which reaches zero
    // up to two seconds before the orchestrator broadcasts the terminal event.
    // A probe landing in that window used to pin this line to "run ended — no
    // completion event received" permanently, and the completion that arrived a
    // second later could not undo it. This is the line that gets quoted.
    const reconciled = reduceProcessing(
      { ...initialProcessingFor(CASE), active: true, processed: 389204 },
      { type: 'run-ended-unobserved' },
    )
    const completed = reduceProcessing(reconciled, {
      event_type: 'ProcessingComplete',
      case_id: CASE,
      total_artifacts: 412806,
      total_duration_ms: 41_200,
      artifacts_by_type: [],
    })
    strip(completed)
    expect(screen.getByText(/complete · 412,806 artifacts/)).toBeInTheDocument()
    expect(
      screen.queryByText(/run ended — no completion event received/),
    ).not.toBeInTheDocument()
  })

  it('counts every module error, including those the bounded list dropped', () => {
    strip({
      ...initialProcessingFor(CASE),
      active: true,
      lastEventAt: NOW,
      errors: [
        { case_id: CASE, module_id: 'plugin.x', artifact_id: 'a', error: 'boom' },
      ],
      errorsDropped: 9_999,
    })
    expect(screen.getByText(/10,000 module errors/)).toBeInTheDocument()
  })
})
