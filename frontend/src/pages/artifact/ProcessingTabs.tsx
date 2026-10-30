import { useRef } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  getArtifactJobs,
  getProcessingHistory,
  listModules,
  runModule,
} from '../../api/resources'
import type { Job } from '../../api/types'
import { useToast } from '../../components/toast/ToastProvider'
import { formatUtc } from '../../lib/format'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { formatMs, statusBadgeClass } from './lib'

function unixUtc(seconds: number | null): string {
  if (seconds == null) return '—'
  return formatUtc(new Date(seconds * 1000).toISOString())
}

function useJobsQuery(caseId: string, artifactId: string) {
  return useQuery({
    queryKey: ['artifact-jobs', caseId, artifactId],
    queryFn: () => getArtifactJobs(caseId, artifactId),
    refetchInterval: (query) => {
      const jobs = query.state.data
      return jobs?.some((j) => j.status === 'pending' || j.status === 'running')
        ? 3000
        : false
    },
  })
}

function JobsTable({ jobs }: { jobs: Job[] }) {
  if (jobs.length === 0) {
    return <p className="av-note">No ad-hoc jobs for this artifact.</p>
  }
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Module</th>
          <th>Status</th>
          <th>Artifacts</th>
          <th>Created</th>
          <th>Completed</th>
          <th>Error</th>
        </tr>
      </thead>
      <tbody>
        {jobs.map((job) => (
          <tr key={job.id}>
            <td className="mono">{job.module_id}</td>
            <td>
              <span className={statusBadgeClass(job.status)}>
                {job.status}
              </span>
            </td>
            <td>{job.artifacts_produced}</td>
            <td className="mono">{unixUtc(job.created_at)}</td>
            <td className="mono">{unixUtc(job.completed_at)}</td>
            <td>{job.error_message ?? '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function ProcessingTab({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  const historyQuery = useQuery({
    queryKey: ['artifact-processing-history', caseId, artifactId],
    queryFn: () => getProcessingHistory(caseId, artifactId),
  })
  const jobsQuery = useJobsQuery(caseId, artifactId)

  return (
    <div>
      <div className="panel">
        <h3 className="panel-title">Processing history</h3>
        {historyQuery.isPending && (
          <div className="loading">Loading processing history...</div>
        )}
        {historyQuery.isError && (
          <div className="error-note">
            Failed to load processing history: {historyQuery.error.message}
          </div>
        )}
        {historyQuery.data?.truncated && (
          <p className="av-note" role="note">
            This history stopped at the server's limit. Earlier module runs
            exist that are not listed.
          </p>
        )}
        {historyQuery.data &&
          (historyQuery.data.items.length === 0 ? (
            <p className="av-note">No modules have run on this artifact.</p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Module</th>
                  <th>Status</th>
                  <th>Artifacts</th>
                  <th>Duration</th>
                  <th>When</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {historyQuery.data.items.map((entry) => (
                  <tr key={entry.id}>
                    <td className="mono">{entry.module_id}</td>
                    <td>
                      <span className={statusBadgeClass(entry.status)}>
                        {entry.status}
                      </span>
                    </td>
                    <td>{entry.artifacts_produced}</td>
                    <td>{formatMs(entry.duration_ms)}</td>
                    <td className="mono">{unixUtc(entry.created_at)}</td>
                    <td>{entry.error_message ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ))}
      </div>
      <div className="panel">
        <h3 className="panel-title">Ad-hoc jobs</h3>
        {jobsQuery.isPending && <div className="loading">Loading jobs...</div>}
        {jobsQuery.isError && (
          <div className="error-note">
            Failed to load jobs: {jobsQuery.error.message}
          </div>
        )}
        {jobsQuery.data && <JobsTable jobs={jobsQuery.data} />}
      </div>
    </div>
  )
}

export function RunModuleTab({
  caseId,
  artifactId,
  artifactType,
}: {
  caseId: string
  artifactId: string
  artifactType: string
}) {
  const toast = useToast()
  const queryClient = useQueryClient()
  // The module list is per artifact type, and this tab stays mounted while the
  // examiner moves between artifacts. A module id chosen for the previous
  // artifact is not necessarily offered for the new one: the `<select>` then
  // renders blank (no matching option) while the state still holds the old id
  // and Run stays enabled, so pressing it starts a module the examiner cannot
  // see against an artifact it does not subscribe to. Scoping the choice to the
  // artifact it was made for means the blank select and the empty state agree
  // (B2-120).
  const [moduleId, setModuleId] = useEntityScopedState(
    `${caseId}/${artifactId}/${artifactType}`,
    '',
  )

  const modulesQuery = useQuery({
    queryKey: ['modules', artifactType],
    queryFn: () => listModules(artifactType),
  })
  const jobsQuery = useJobsQuery(caseId, artifactId)
  // The artifact a run must have been started against for its result to belong
  // here. Assigned during render, not from an effect.
  const activeTarget = useRef({ caseId, artifactId })
  activeTarget.current = { caseId, artifactId }

  const runMutation = useMutation({
    mutationFn: (id: string) => {
      // Bind the target at call time: this panel outlives an artifact (and a
      // case) change, and `onSuccess` runs in the latest render's closure, so
      // reading them there would refresh whichever artifact is on screen rather
      // than the one the module was started for (B5-012 class).
      const target = { caseId, artifactId }
      return runModule(target.caseId, target.artifactId, id).then((result) => ({
        result,
        target,
      }))
    },
    // Name the module that was actually submitted, not whatever the selector
    // holds by the time the response lands.
    onSuccess: ({ result, target }, startedId) => {
      queryClient.invalidateQueries({
        queryKey: ['artifact-jobs', target.caseId, target.artifactId],
      })
      const where =
        target.caseId === activeTarget.current.caseId &&
        target.artifactId === activeTarget.current.artifactId
          ? ''
          : ' on the artifact it was started from, not the one open now'
      toast.success(
        `Module ${startedId} started (job ${result.job_id})` + where,
      )
    },
    onError: (error) => toast.error(`Failed to start module: ${error.message}`),
  })

  return (
    <div>
      <div className="panel">
        <h3 className="panel-title">Run a module against this artifact</h3>
        {modulesQuery.isPending && (
          <div className="loading">Loading modules...</div>
        )}
        {modulesQuery.isError && (
          <div className="error-note">
            Failed to load modules: {modulesQuery.error.message}
          </div>
        )}
        {modulesQuery.data &&
          (modulesQuery.data.length === 0 ? (
            <p className="av-note">
              No modules subscribe to {artifactType} artifacts.
            </p>
          ) : (
            <div className="av-run-form">
              <label>
                Module
                <select
                  className="select"
                  value={moduleId}
                  onChange={(e) => setModuleId(e.target.value)}
                >
                  <option value="">Select a module</option>
                  {modulesQuery.data.map((mod) => (
                    <option key={mod.id} value={mod.id}>
                      {mod.id} ({mod.version})
                    </option>
                  ))}
                </select>
              </label>
              <button
                className="btn btn-primary"
                disabled={!moduleId || runMutation.isPending}
                onClick={() => runMutation.mutate(moduleId)}
              >
                Run
              </button>
            </div>
          ))}
      </div>
      <div className="panel">
        <h3 className="panel-title">Recent jobs</h3>
        {jobsQuery.isPending && <div className="loading">Loading jobs...</div>}
        {jobsQuery.isError && (
          <div className="error-note">
            Failed to load jobs: {jobsQuery.error.message}
          </div>
        )}
        {jobsQuery.data && <JobsTable jobs={jobsQuery.data} />}
      </div>
    </div>
  )
}
