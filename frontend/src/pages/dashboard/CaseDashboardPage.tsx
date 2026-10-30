import { useQuery } from '@tanstack/react-query'
import { useEffect } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useProcessingActive } from '../../app/ProcessingContext'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import {
  getActiveProfile,
  getCaseStats,
  getRecentArtifacts,
  listJobs,
  listModules,
} from '../../api/resources'
import type { Job } from '../../api/types'
import { resolveProfileGovernance } from '../../components/ingest/profileScope'
import { ProfileScopeNote } from '../../components/ingest/ProfileScopeNote'
import { useToast } from '../../components/toast/ToastProvider'
import { MiniTimeline } from '../../components/viz/MiniTimeline'
import { downloadFile } from '../../lib/download'
import { formatCount, formatUtc } from '../../lib/format'
import { getTimelineHistogram } from '../timeline/api'
import { getFileSizeStats } from './api'
import { FileSizeColumns, TypeBarChart } from './charts'
import { humanizeArtifactTypePlural } from './labels'
import { shouldPollCasePanels } from './polling'
import { histogramEventTotal } from './timelineTotal'
import { AttentionPanel } from './AttentionPanel'
import { SourcesSection } from './SourcesSection'
import './dashboard.css'

function jobBadgeClass(status: Job['status']): string {
  if (status === 'running') return 'badge badge-accent'
  if (status === 'complete') return 'badge badge-ok'
  if (status === 'failed') return 'badge badge-danger'
  return 'badge'
}

function JobsTable({ jobs }: { jobs: Job[] }) {
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Module</th>
          <th>Status</th>
          <th>Artifacts</th>
          <th>Error</th>
        </tr>
      </thead>
      <tbody>
        {jobs.map((job) => (
          <tr key={job.id}>
            <td className="mono">{job.module_id}</td>
            <td>
              <span className={jobBadgeClass(job.status)}>{job.status}</span>
            </td>
            <td className="mono">{job.artifacts_produced}</td>
            <td className="dash-error-cell">{job.error_message ?? '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/**
 * The report formats the dashboard offers, each `GET /cases/{id}/export/{format}`
 * in `seance_api` (`export_case_html_report`, `export_case_pdf`,
 * `export_case_docx`, `export_case_rtf`, `export_case_xml`, and the XLSX
 * workbook). One report, rendered by the reporting crate in each.
 */
type ReportFormat = 'html' | 'pdf' | 'docx' | 'rtf' | 'xml' | 'xlsx'

export function CaseDashboardPage() {
  const { caseId } = useParams() as { caseId: string }
  const toast = useToast()
  // This page stays mounted when `:caseId` changes, and both of these name the
  // case they were set under. "Show completed jobs" expanded for case A stayed
  // expanded over case B's job list; more importantly a report export started
  // for case A left case B's Export button disabled, which reads as "an export
  // of THIS case is already running" (B2-150).
  const [showCompleted, setShowCompleted] = useEntityScopedState(caseId, false)
  const [exporting, setExporting] = useEntityScopedState<ReportFormat | null>(
    caseId,
    null,
  )

  const processingActive = useProcessingActive()

  const jobsQuery = useQuery({
    // Keyed to match the ['jobs', caseId] invalidations fired from Gallery /
    // NavigatorPanel / UnlockPanel, so queued work refreshes the dashboard.
    queryKey: ['jobs', caseId],
    queryFn: () => listJobs(caseId),
    refetchInterval: (query) =>
      query.state.data?.items.some(
        (j) => j.status === 'pending' || j.status === 'running',
      )
        ? 3000
        : false,
  })
  // While an ingest job is running, poll the stats/recent panels so the
  // dashboard fills in live instead of sitting on the empty state until the
  // run completes (completion also invalidates these via useProcessingEvents).
  const ingesting = shouldPollCasePanels({
    jobsActive: (jobsQuery.data?.items ?? []).some(
      (j) => j.status === 'pending' || j.status === 'running',
    ),
    // Ingesting evidence creates no ad-hoc job, so the job list alone left this
    // page frozen for the whole of every run (LIVE-021).
    processingActive,
  })
  const statsQuery = useQuery({
    queryKey: ['case', caseId, 'stats'],
    queryFn: () => getCaseStats(caseId),
    refetchInterval: ingesting ? 4000 : false,
  })
  const recentQuery = useQuery({
    queryKey: ['case', caseId, 'recent'],
    queryFn: () => getRecentArtifacts(caseId),
    refetchInterval: ingesting ? 4000 : false,
  })
  const fileSizesQuery = useQuery({
    queryKey: ['case', caseId, 'stats', 'file_sizes'],
    queryFn: () => getFileSizeStats(caseId),
    retry: false,
    // Every panel on this page polls together or the page contradicts itself:
    // a frozen size histogram beside live tiles reads as "no file size data"
    // for a case that is filling up (the LIVE-021 class).
    refetchInterval: ingesting ? 4000 : false,
  })
  const histogramQuery = useQuery({
    queryKey: ['case', caseId, 'timeline', 'histogram', 'dashboard'],
    queryFn: () => getTimelineHistogram(caseId, { buckets: 80 }),
    retry: false,
    // Polls with the other panels. Without this the activity chart and the
    // event count beside it stayed frozen for the whole of an ingest while the
    // tiles above them counted past a hundred thousand — LIVE-021's symptom,
    // in the one panel LIVE-025 was raised about.
    refetchInterval: ingesting ? 4000 : false,
  })

  // The profile in force on the case. It is the one piece of case state that
  // silently decides what this whole page can ever show: a module the profile
  // excludes produces no job, no log row and no stamp, so its results are
  // absent from every panel here in exactly the way evidence that had none
  // would be. Read on the dashboard because this is the screen an examiner
  // inheriting a case reads first (S3), and the screen quoted from (S4).
  const activeProfileQuery = useQuery({
    queryKey: ['profile-active', caseId],
    queryFn: () => getActiveProfile(caseId),
    retry: false,
  })
  const modulesQuery = useQuery({
    queryKey: ['modules', 'all'],
    queryFn: () => listModules(),
    retry: false,
    staleTime: 5 * 60 * 1000,
  })
  const registry = modulesQuery.data?.map((m) => m.id)
  const governance = resolveProfileGovernance({
    // The dashboard reports the state, it does not choose it, so it always asks
    // about the profile the case is running under.
    selection: '',
    profiles: [],
    active: activeProfileQuery.isError ? undefined : activeProfileQuery.data,
    registry,
  })
  // A pending lookup is not a failed one, and a case with no profile has
  // nothing to disclose: a banner an examiner meets on every case is a banner
  // they stop reading.
  const showProfileNote =
    !activeProfileQuery.isPending &&
    !modulesQuery.isPending &&
    governance.kind !== 'none'

  // The artifact census counts stored TimelineEvent records; the timeline is
  // mostly derived from file MAC times, so the census understated one real case
  // by 3,600x (LIVE-025). The histogram this panel already loads is the honest
  // count.
  const timelineTotal = histogramEventTotal(histogramQuery.data)

  useEffect(() => {
    if (fileSizesQuery.error) {
      console.warn('file size stats unavailable', fileSizesQuery.error)
    }
  }, [fileSizesQuery.error])

  async function handleExport(format: ReportFormat) {
    setExporting(format)
    try {
      await downloadFile(
        `/cases/${caseId}/export/${format}`,
        `report-${caseId}.${format}`,
      )
    } catch {
      toast.error(
        `${format.toUpperCase()} export failed. Click Export ${format.toUpperCase()} to retry.`,
      )
    } finally {
      setExporting(null)
    }
  }

  if (statsQuery.isPending) {
    return <div className="loading">Loading dashboard…</div>
  }
  if (statsQuery.isError) {
    return <div className="error-note">{statsQuery.error.message}</div>
  }

  const stats = statsQuery.data
  const jobs = jobsQuery.data?.items ?? []
  // The job list has a ceiling. An examiner reading this panel to decide
  // whether an analysis was ever run would otherwise take a job's absence as
  // proof it never happened, when it was only past the limit.
  const jobsTruncated = jobsQuery.data?.truncated === true
  // A failed job is finished, not running. Filing it under "active" made the
  // dashboard claim work was still in progress that had in fact stopped, and
  // hid the failure from the examiner reading the panel for run state (B7-033).
  const activeJobs = jobs.filter(
    (j) => j.status === 'pending' || j.status === 'running',
  )
  const failedJobs = jobs.filter((j) => j.status === 'failed')
  const completedJobs = jobs.filter((j) => j.status === 'complete')
  // Any status the API adds that this page does not know about. Shown rather
  // than dropped: a job that exists must not vanish because its state is
  // unrecognised.
  const otherJobs = jobs.filter(
    (j) =>
      j.status !== 'pending' &&
      j.status !== 'running' &&
      j.status !== 'failed' &&
      j.status !== 'complete',
  )
  const recent = recentQuery.data ?? []

  return (
    <div>
      <h1 className="page-title">Dashboard</h1>
      <div className="page-actions">
        <button
          className="btn"
          disabled={exporting === 'html'}
          onClick={() => handleExport('html')}
        >
          Export HTML
        </button>
        <button
          className="btn"
          disabled={exporting === 'pdf'}
          onClick={() => handleExport('pdf')}
        >
          Export PDF
        </button>
        {/* The same report as a Word document (ROADMAP §2.10), as RTF and as
            XML for tools that read the report as data. The RTF and XML routes
            existed with nothing in the UI reaching them; DOCX landed the same
            way. Each button fetches its own route, so a failure in one
            format is reported against that format alone. */}
        <button
          className="btn"
          disabled={exporting === 'docx'}
          onClick={() => handleExport('docx')}
        >
          Export DOCX
        </button>
        <button
          className="btn"
          disabled={exporting === 'rtf'}
          onClick={() => handleExport('rtf')}
        >
          Export RTF
        </button>
        <button
          className="btn"
          disabled={exporting === 'xml'}
          onClick={() => handleExport('xml')}
        >
          Export XML
        </button>
        {/* The same report as a workbook, one sheet per section. The route
            existed for a year with nothing in the UI reaching it. */}
        <button
          className="btn"
          disabled={exporting === 'xlsx'}
          onClick={() => handleExport('xlsx')}
        >
          Export XLSX
        </button>
      </div>

      {showProfileNote && (
        <ProfileScopeNote
          governance={governance}
          context="case"
          registered={registry?.length ?? null}
        />
      )}

      {stats.total_artifacts === 0 ? (
        <div className="empty-state">
          <h3>No evidence in this case yet</h3>
          <p>
            Use the Ingest Evidence button in the sidebar to add a disk image,
            container, or file to begin processing.
          </p>
        </div>
      ) : (
        <>
          <div className="dash-stats">
            <div className="dash-stat-card dash-stat-total">
              <div className="dash-stat-value">
                {formatCount(stats.total_artifacts)}
              </div>
              <div className="dash-stat-label">Total artifacts</div>
            </div>
            {Object.entries(stats.artifact_counts_by_type)
              .sort(([, a], [, b]) => b - a)
              .map(([type, count]) => (
                <div key={type} className="dash-stat-card">
                  <div className="dash-stat-value">{formatCount(count)}</div>
                  <div className="dash-stat-label">
                    {humanizeArtifactTypePlural(type)}
                  </div>
                </div>
              ))}
          </div>

          <div className="dash-charts">
            <div className="panel dash-chart-panel">
              <h2 className="panel-title">Artifacts by type</h2>
              <TypeBarChart counts={stats.artifact_counts_by_type} />
            </div>
            {/* A failed secondary query keeps its panel, showing why the chart
                is missing. Silently dropping the panel made a failed query look
                identical to "this case has no such data" (BUG-204). */}
            <div className="panel dash-chart-panel">
              <h2 className="panel-title">File size distribution</h2>
              {fileSizesQuery.isPending && (
                <div className="dash-skel" style={{ height: 142 }} />
              )}
              {fileSizesQuery.isError && (
                <div className="error-note" role="note">
                  File size distribution unavailable:{' '}
                  {fileSizesQuery.error.message}
                </div>
              )}
              {fileSizesQuery.data && (
                <FileSizeColumns buckets={fileSizesQuery.data.buckets} />
              )}
            </div>
          </div>

          <div className="panel dash-timeline-panel">
            <div className="dash-timeline-head">
              <h2 className="panel-title">
                Case activity over time
                {timelineTotal !== null && (
                  <span className="dash-panel-count">
                    {' '}
                    {formatCount(timelineTotal)} events
                  </span>
                )}
              </h2>
              <Link className="link-button" to={`/cases/${caseId}/timeline`}>
                Open timeline
              </Link>
            </div>
            {histogramQuery.isError ? (
              <div className="error-note" role="note">
                Case activity chart unavailable: {histogramQuery.error.message}
              </div>
            ) : histogramQuery.isPending || !histogramQuery.data ? (
              <div className="dash-skel" style={{ height: 88 }} />
            ) : (
              <MiniTimeline
                buckets={histogramQuery.data.buckets}
                minTs={histogramQuery.data.min_ts}
                maxTs={histogramQuery.data.max_ts}
                bucketSeconds={histogramQuery.data.bucket_seconds}
              />
            )}
          </div>

          {/* Above the sources, because it is the one panel on this page that
              asks the examiner to DO something rather than telling them what
              the case holds (§2.11). */}
          <AttentionPanel caseId={caseId} />

          <SourcesSection caseId={caseId} />

          <div className="panel">
            <h2 className="panel-title">Recent activity</h2>
            {recentQuery.isPending && (
              <div className="loading">Loading recent artifacts…</div>
            )}
            {recentQuery.isError && (
              <div className="error-note">{recentQuery.error.message}</div>
            )}
            {recentQuery.isSuccess &&
              (recent.length === 0 ? (
                <div className="dash-muted">No recent artifacts.</div>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Type</th>
                      <th>Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recent.map((a) => (
                      <tr key={a.id}>
                        <td>
                          <Link to={`/cases/${caseId}/artifacts/${a.id}`}>
                            {a.display_name}
                          </Link>
                        </td>
                        <td>
                          <span className="badge">{a.artifact_type}</span>
                        </td>
                        <td className="mono">{formatUtc(a.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ))}
          </div>
        </>
      )}

      <div className="panel">
        <h2 className="panel-title">Processing jobs</h2>
        {jobsQuery.isPending && <div className="loading">Loading jobs…</div>}
        {jobsQuery.isError && (
          <div className="error-note">{jobsQuery.error.message}</div>
        )}
        {jobsQuery.isSuccess && (
          <>
            {jobsTruncated && (
              <div className="dash-note" role="note">
                This list stopped at the server's limit. Jobs exist that are not
                shown, so an absence here is not evidence a module never ran.
              </div>
            )}
            {/* "No active jobs" is true of this list and false of the case
                whenever an ingest is running: an ingest creates no job row, so
                the panel reported an idle case while the processing panel above
                it counted through a hundred thousand artifacts. That is a false
                absence on the screen an examiner reads to answer "is anything
                still running". The list is still only module jobs; the sentence
                now says which of the two things it is reporting. */}
            {activeJobs.length === 0 ? (
              processingActive ? (
                <div className="dash-muted" data-testid="dash-ingest-running">
                  No module jobs. An evidence ingest is running now — it does
                  not appear here, because this list holds module runs started
                  against artifacts already in the case. Its progress is in the
                  processing panel.
                </div>
              ) : (
                <div className="dash-muted">No active jobs.</div>
              )
            ) : (
              <JobsTable jobs={activeJobs} />
            )}
            {failedJobs.length > 0 && (
              <div data-testid="dash-failed-jobs">
                <h3 className="dash-jobs-subhead">
                  Failed jobs ({failedJobs.length})
                </h3>
                <JobsTable jobs={failedJobs} />
              </div>
            )}
            {otherJobs.length > 0 && (
              <div data-testid="dash-other-jobs">
                <h3 className="dash-jobs-subhead">
                  Jobs in an unrecognised state ({otherJobs.length})
                </h3>
                <JobsTable jobs={otherJobs} />
              </div>
            )}
            {completedJobs.length > 0 && (
              <>
                <button
                  className="btn dash-completed-toggle"
                  aria-expanded={showCompleted}
                  onClick={() => setShowCompleted((v) => !v)}
                >
                  Completed jobs ({completedJobs.length})
                </button>
                {showCompleted && <JobsTable jobs={completedJobs} />}
              </>
            )}
          </>
        )}
      </div>
    </div>
  )
}
