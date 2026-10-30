import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import { SkeletonList } from '../../components/Skeleton'
import { formatBytes, formatCount } from '../../lib/format'
import {
  getMemoryCoverage,
  getMemoryProcesses,
  getMemoryTampering,
  type MemoryCoverageResponse,
  type MemoryProcessesResponse,
  type StageEnvelope,
} from './api'
import { useMemoryContext } from './memoryContext'
import { FindingCard, SEVERITY_ORDER, severityOf } from './FindingCard'
import {
  envelopeStatus,
  failureSummary,
  formatQualifiedCount,
  readProcesses,
  readTamperingSignals,
  terminated,
} from './normalize'

/**
 * Triage: what should an examiner look at first.
 *
 * A findings list and a coverage summary, not a plugin menu. The three things
 * it must get right are the three ways a triage screen misleads: a tile whose
 * count came from a capped enumeration must say the number is a floor; a lens
 * whose stage never ran must show as *not run* rather than as a zero; and a
 * capture with no tampering signal must not be presented as a clean machine.
 */

const TOP_FINDINGS = 6

export function MemoryOverviewPage() {
  const { caseId, imageId, image, scopeKey } = useMemoryContext()

  const coverageQuery = useEntityScopedQuery<MemoryCoverageResponse>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'coverage'],
    queryFn: () => getMemoryCoverage(caseId, imageId),
    retry: false,
  })
  const processQuery = useEntityScopedQuery<MemoryProcessesResponse>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'processes'],
    queryFn: () => getMemoryProcesses(caseId, imageId),
    retry: false,
  })
  const tamperingQuery = useEntityScopedQuery<StageEnvelope>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'tampering'],
    queryFn: () => getMemoryTampering(caseId, imageId),
    retry: false,
  })

  const coverage = coverageQuery.scoped
  const processes = useMemo(
    () => readProcesses(processQuery.scoped?.list),
    [processQuery.scoped],
  )
  // Two levels down inside the one scan record, not a top-level row array —
  // `readStageRows` reached none of them and fell back to the whole record as a
  // single row, so this tile read "1" and the panel below showed one titleless
  // card on every capture, clean or not.
  const tampering = useMemo(
    () => readTamperingSignals(tamperingQuery.scoped),
    [tamperingQuery.scoped],
  )
  const signals = tampering.rows

  const topSignals = useMemo(
    () =>
      [...signals]
        .sort(
          (a, b) =>
            (SEVERITY_ORDER[severityOf(a)] ?? 9) -
            (SEVERITY_ORDER[severityOf(b)] ?? 9),
        )
        .slice(0, TOP_FINDINGS),
    [signals],
  )

  const processStatus = envelopeStatus(processQuery.scoped?.list)
  const tamperingStatus = envelopeStatus(tamperingQuery.scoped)
  const exited = processes.filter((row) => row.hasExited).length

  const memPath = (lens: string) =>
    `/cases/${caseId}/memory/${lens}?image=${encodeURIComponent(imageId)}`

  return (
    <div className="mem-overview">
      <section className="panel mem-strip" aria-labelledby="mem-strip-title">
        <h2 className="panel-title" id="mem-strip-title">
          {image.name ?? image.image_id}
        </h2>
        <p className="mem-strip-facts">
          <span className="mono">{formatBytes(image.addressable_bytes)}</span>{' '}
          addressable ·{' '}
          <span>{image.architecture ?? 'architecture not established'}</span>
        </p>
        <p className="mem-note">{image.analysis_state_meaning}</p>
        <p>
          <Link className="link-button" to={memPath('image')}>
            What this rests on
          </Link>
        </p>
      </section>

      <section className="panel" aria-labelledby="mem-tiles-title">
        <h2 className="panel-title" id="mem-tiles-title">
          What is in this capture
        </h2>
        <div className="mem-tiles">
          <Tile
            to={memPath('processes')}
            label="processes"
            status={processStatus.kind}
            value={
              processQuery.scoped == null
                ? null
                : formatQualifiedCount(processes.length, [
                    { count: exited, label: 'exited' },
                  ])
            }
          />
          <Tile
            to={memPath('findings')}
            label="tampering signals"
            status={tamperingStatus.kind}
            value={
              tamperingQuery.scoped == null
                ? null
                : formatQualifiedCount(signals.length, [
                    {
                      count: tampering.unreadable,
                      label: 'records unreadable',
                    },
                  ])
            }
          />
        </div>
      </section>

      <section className="panel" aria-labelledby="mem-coverage-title">
        <h2 className="panel-title" id="mem-coverage-title">
          What ran
        </h2>
        {coverageQuery.isPending || coverageQuery.stale ? (
          <SkeletonList rows={4} label="Loading stage coverage" />
        ) : coverageQuery.isError || coverage == null ? (
          <div className="error-note" role="note">
            Stage coverage could not be loaded. Without it there is no way to
            tell which lenses are empty because nothing was found and which are
            empty because nothing ran, so treat every count on this page as
            unqualified.
          </div>
        ) : (
          <>
            <p className="mem-note">
              {coverage.summary.complete} of {coverage.summary.total_stages}{' '}
              stages completed. {coverage.summary.did_not_run} did not run,{' '}
              {coverage.summary.failed} failed, {coverage.summary.incomplete}{' '}
              finished short.
            </p>
            <ul className="mem-signals">
              {coverage.stages
                .filter(
                  (stage) =>
                    stage.status === 'did_not_run' || stage.status === 'failed',
                )
                .map((stage) => (
                  <li className="mem-signal mem-signal-warning" key={stage.stage}>
                    <span className="mem-signal-summary">
                      <span className="mono">{stage.stage}</span>:{' '}
                      {stage.status.replace(/_/g, ' ')}
                    </span>
                    <span className="mem-note">
                      {stage.status_meaning}{' '}
                      {failureSummary(stage.failures)}
                    </span>
                  </li>
                ))}
            </ul>
            {coverage.summary.did_not_run + coverage.summary.failed === 0 && (
              <p className="mem-note">
                Every stage ran. That is not a statement that the machine was
                clean — only that no lens below is empty for want of an analysis.
              </p>
            )}
            <Link className="btn" to={memPath('image')}>
              Full coverage table
            </Link>
          </>
        )}
      </section>

      <section className="panel" aria-labelledby="mem-findings-title">
        <h2 className="panel-title" id="mem-findings-title">
          Tampering signals
        </h2>
        {tamperingQuery.isPending || tamperingQuery.stale ? (
          <SkeletonList rows={4} label="Loading tampering signals" />
        ) : tamperingQuery.isError ? (
          <div className="error-note" role="note">
            Tampering signals could not be loaded. This is a load error, not an
            absence of signals.
          </div>
        ) : tamperingStatus.kind === 'not_run' ? (
          <div className="error-note" role="note">
            <strong>The tampering scan did not run on this capture.</strong>{' '}
            {terminated(tamperingStatus.message)} An empty list here would read as an
            exculpatory finding, so none is shown.
          </div>
        ) : topSignals.length === 0 &&
          (tamperingStatus.kind === 'partial' ||
            tamperingStatus.kind === 'undetermined') ? (
          // The scan stopped early and produced nothing decodable. Its silence
          // is not the exculpatory finding the empty state below would state.
          <div className="warn-note" role="note">
            <strong>The tampering scan did not finish on this capture.</strong>{' '}
            {terminated(tamperingStatus.message)} No signal is listed, and that is not a
            finding that there was none.
          </div>
        ) : topSignals.length === 0 && tampering.unreadable > 0 ? (
          // The scan's records were in a shape this client could not read. The
          // empty copy below states that the scan found nothing, which is an
          // exculpatory finding nobody established here.
          <div className="error-note" role="note">
            <strong>The tampering records could not be read.</strong>{' '}
            {formatCount(tampering.unreadable)} record
            {tampering.unreadable === 1 ? '' : 's'} came back in a shape this
            client does not recognise. No signal is listed, and that is not a
            finding that there was none.
          </div>
        ) : topSignals.length === 0 ? (
          <div className="empty-state">
            <h3>No tampering signal was recorded</h3>
            <p>
              The scan ran and recorded nothing. That covers image hollowing,
              process ghosting and executable memory with no file behind it, and
              nothing else.
            </p>
          </div>
        ) : (
          <>
            {tamperingStatus.kind === 'partial' && (
              <div className="warn-note" role="note">
                <strong>This list is a floor.</strong>{' '}
                {terminated(tamperingStatus.message)}
              </div>
            )}
            <div className="mem-finding-list">
              {topSignals.map((row) => (
                <FindingCard
                  key={row.key}
                  row={row}
                  caseId={caseId}
                  imageId={imageId}
                />
              ))}
            </div>
            {signals.length > TOP_FINDINGS && (
              <Link className="btn" to={memPath('findings')}>
                Show all {signals.length} signals
              </Link>
            )}
          </>
        )}
      </section>
    </div>
  )
}

/**
 * A count tile that refuses to render a number it cannot stand behind.
 *
 * A stage that did not run shows "not run", never `0`. That single substitution
 * is the difference between "this machine had no tampering signals" and "the
 * tampering scanner never executed".
 */
function Tile({
  to,
  label,
  value,
  status,
}: {
  to: string
  label: string
  value: string | null
  status: ReturnType<typeof envelopeStatus>['kind']
}) {
  const spoken =
    status === 'not_run'
      ? 'not run'
      : status === 'undetermined'
        ? 'not determined'
        : value == null
          ? 'not reported'
          : `${value}${status === 'partial' ? ', a floor' : ''}`
  return (
    // The accessible name leads with what the tile counts and then states the
    // number *or* the reason there is none, so a screen reader never hears a
    // bare count for a stage that produced none.
    <Link className="mem-tile" to={to} aria-label={`${label}: ${spoken}`}>
      <span className="mem-tile-value">
        {status === 'not_run' ? (
          <span className="badge badge-danger">not run</span>
        ) : status === 'undetermined' ? (
          <span className="badge badge-warn">not determined</span>
        ) : value == null ? (
          <span className="badge badge-warn">not reported</span>
        ) : (
          value
        )}
      </span>
      <span className="mem-tile-label">{label}</span>
      {status === 'partial' && (
        <span className="badge badge-warn mem-tile-floor">floor</span>
      )}
    </Link>
  )
}
