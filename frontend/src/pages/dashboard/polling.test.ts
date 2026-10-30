// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { shouldPollCasePanels } from './polling'

/**
 * LIVE-021: the dashboard decided it was busy by looking at the ad-hoc JOB
 * list, but ingesting evidence creates no ad-hoc job. During a real 35 GB
 * ingest the job list stayed empty, so the tiles never polled: the footer read
 * "processing · 132,366 artifacts" while the dashboard beside it still showed
 * "1 total artifact", "No dated events" and "Processing jobs: No active jobs".
 * Only a manual reload revealed the true figures.
 */
describe('shouldPollCasePanels', () => {
  it('polls while evidence is being processed, even with no ad-hoc job', () => {
    expect(
      shouldPollCasePanels({ jobsActive: false, processingActive: true }),
    ).toBe(true)
  })

  it('polls while an ad-hoc job runs, even with no ingest', () => {
    expect(
      shouldPollCasePanels({ jobsActive: true, processingActive: false }),
    ).toBe(true)
  })

  it('stops polling when nothing is running', () => {
    expect(
      shouldPollCasePanels({ jobsActive: false, processingActive: false }),
    ).toBe(false)
  })
})
