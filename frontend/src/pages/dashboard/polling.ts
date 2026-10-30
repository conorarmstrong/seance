/**
 * Whether the case panels (stats, recent activity) should keep polling.
 *
 * Two independent things make a case change under the examiner: an ad-hoc
 * module job, and an evidence ingest. Only the first creates a row in the job
 * list, so a dashboard that asked the job list alone sat frozen through every
 * ingest — showing "1 total artifact" and "No active jobs" while the status bar
 * directly beneath it counted past a hundred thousand (LIVE-021). The ingest
 * signal comes from the case's SSE stream instead.
 */
export function shouldPollCasePanels(state: {
  jobsActive: boolean
  processingActive: boolean
}): boolean {
  return state.jobsActive || state.processingActive
}
