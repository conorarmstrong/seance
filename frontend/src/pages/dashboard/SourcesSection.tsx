import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ApiRequestError } from '../../api/http'
import { getArtifact } from '../../api/resources'
import { IncompleteBadge } from '../../components/Incompleteness'
import { AllocationMap } from '../../components/viz/AllocationMap'
import { getAllocationMap, getDiskMap } from '../../components/viz/api'
import type { DiskMapRegion } from '../../components/viz/api'
import { DiskMap } from '../../components/viz/DiskMap'
import {
  incompleteReasonLabel,
  incompletenessSentence,
  readIncompleteness,
} from '../../lib/incompleteness'
import {
  getSourceKinds,
  getSourceStats,
  type SourceKindRow,
  type SourceKindsResponse,
  type SourceStat,
} from './api'
import { fsUsageLabel } from './labels'
import { formatCount } from '../../lib/format'

/**
 * Collapsible per-filesystem allocation view. Lazy-fetches the
 * allocation map on first expand; hides itself entirely when the
 * filesystem has no map (404).
 */
function FsUsage({ caseId, region }: { caseId: string; region: DiskMapRegion }) {
  const [expanded, setExpanded] = useState(false)
  const [requested, setRequested] = useState(false)

  const allocQuery = useQuery({
    queryKey: ['case', caseId, 'allocation', region.artifact_id],
    queryFn: () => getAllocationMap(caseId, region.artifact_id),
    enabled: requested,
    retry: false,
    staleTime: Infinity,
  })

  const missing =
    allocQuery.error instanceof ApiRequestError && allocQuery.error.status === 404

  // 404 means this filesystem has no allocation map at all, so there is nothing
  // to offer. Any other failure keeps the row and says what happened: a
  // vanished section reads as "this filesystem has no usage to show", which is
  // a statement about the evidence that a failed request cannot support
  // (B8-021, the BUG-204 class).
  if (missing) return null

  const label = fsUsageLabel(region)

  return (
    <div className="dash-fs-usage">
      <button
        className="link-button dash-fs-toggle"
        aria-expanded={expanded}
        onClick={() => {
          setExpanded((v) => !v)
          setRequested(true)
        }}
      >
        Disk usage — {label}
      </button>
      {expanded && allocQuery.isPending && requested && (
        <div className="dash-skel" style={{ height: 80 }} />
      )}
      {expanded && allocQuery.isError && (
        <div className="error-note" role="note">
          Disk usage for {label} could not be loaded:{' '}
          {(allocQuery.error as Error).message}. This is a failed request, not a
          filesystem with nothing allocated.
        </div>
      )}
      {expanded && allocQuery.data && <AllocationMap data={allocQuery.data} />}
    </div>
  )
}

/**
 * What a source's acquisition state means for the artifact count beside it.
 *
 * The count and the state are two facts and an examiner reads them as one line,
 * so the state has to travel with the number. A source whose acquisition hash
 * is still running has not finished being processed, so its zero means "not
 * yet"; a source whose baseline could not be established is an exhibit the case
 * holds and cannot vouch for, so its zero may mean "never read" rather than
 * "empty". Both used to render as a bare "0 artifacts", which reads as "this
 * exhibit contained nothing" — and that reading gets quoted.
 *
 * The two absences are kept apart because they are different facts. `unrecorded`
 * is a source that carries no acquisition state, which an exhibit ingested
 * before the states existed genuinely does not. `unfetched` is a source whose
 * state this response never read: the server takes it off the same root-artifact
 * walk that produces the name, so an unresolved name means the state was not
 * looked up, not that none is on file.
 *
 * A state this file does not recognise is reported verbatim rather than folded
 * into a known one. Nothing here can know what an unfamiliar state implies about
 * the count, and guessing is the failure this card exists to prevent.
 */
type Acquisition =
  | { kind: 'acquired' }
  | { kind: 'acquiring' }
  | { kind: 'failed'; error: string | null }
  | { kind: 'unrecognised'; state: string }
  | { kind: 'unrecorded' }
  | { kind: 'unfetched' }

function readAcquisition(source: SourceStat): Acquisition {
  const state = source.integrity_state ?? null
  if (state === null) {
    return source.name_resolved === false
      ? { kind: 'unfetched' }
      : { kind: 'unrecorded' }
  }
  switch (state) {
    case 'baseline_recorded':
      return { kind: 'acquired' }
    case 'verifying':
      return { kind: 'acquiring' }
    case 'acquisition_failed':
      return { kind: 'failed', error: source.acquisition_error ?? null }
    default:
      return { kind: 'unrecognised', state }
  }
}

/**
 * The state as one chip beside the count, so it is legible at a glance rather
 * than only in the prose underneath. `unfetched` draws nothing: the name note
 * already on that card says why the state is missing, and a second chip saying
 * the same thing in fewer words would only invite the shorter reading.
 */
function AcquisitionBadge({ acquisition }: { acquisition: Acquisition }) {
  switch (acquisition.kind) {
    case 'acquired':
      return (
        <span
          className="badge badge-ok"
          title="This source's acquisition baseline is on file."
        >
          acquired
        </span>
      )
    case 'acquiring':
      return (
        <span className="badge badge-warn" title="Acquisition hash still running.">
          acquiring
        </span>
      )
    case 'failed':
      return (
        <span
          className="badge badge-danger"
          title="No acquisition baseline could be established for this source."
        >
          acquisition failed
        </span>
      )
    case 'unrecognised':
      return (
        <span
          className="badge badge-warn"
          title={`This source's acquisition state is "${acquisition.state}", which this screen does not recognise.`}
        >
          acquisition state: {acquisition.state}
        </span>
      )
    case 'unrecorded':
      return (
        <span
          className="badge"
          title="This source carries no acquisition state, which an exhibit ingested before Séance recorded them does not. That is not a statement that no baseline exists for it."
          aria-label="acquisition state not recorded — this source carries no acquisition state, which an exhibit ingested before Séance recorded them does not. That is not a statement that no baseline exists for it."
        >
          acquisition state not recorded
        </span>
      )
    case 'unfetched':
      return null
  }
}

/**
 * The walk's own outcome, beside the acquisition's (HUNT-113). A source whose
 * processing a killed or cancelled process never finished used to show the
 * same card as one whose walk ended, with the partial count read as a total.
 * Only the two unfinished states draw anything: a completed walk is the
 * ordinary case and needs no chip, and a source with no recorded run gets the
 * prose below rather than a chip that would read as a verdict.
 */
function ProcessingBadge({ state }: { state: string | null | undefined }) {
  switch (state) {
    case 'interrupted':
      return (
        <span
          className="badge badge-danger"
          title="Processing of this source was interrupted by a stopped process before its walk ended."
        >
          processing interrupted
        </span>
      )
    case 'cancelled':
      return (
        <span
          className="badge badge-danger"
          title="Processing of this source was cancelled before its walk ended."
        >
          processing cancelled
        </span>
      )
    case 'running':
      return (
        <span className="badge badge-warn" title="This source is being processed now.">
          processing
        </span>
      )
    default:
      return null
  }
}

const KIND_LABEL: Record<string, string> = {
  android_device: 'Android device',
  android_backup: 'Android backup',
  ios_device: 'iOS device',
  ios_backup: 'iOS backup',
}

/** Where a kind came from, in words: the record types, their files, and how many. */
function basisSentence(row: SourceKindRow): string {
  return row.basis
    .map((b) => {
      const quoted = b.records
        .map((r) =>
          r.source_file ? `${r.record_type} (${r.source_file})` : r.record_type,
        )
        .join(', ')
      return `${KIND_LABEL[b.kind] ?? b.kind} from ${b.marker_records} marker record(s): ${quoted}`
    })
    .join('; ')
}

/** One marker's whole test, as the server applies it: the type, the field
 *  value it must carry, and the path its store must sit at. */
function markerTest(m: SourceKindsResponse['looked_for'][number]): string {
  let test = m.record_type
  if (m.requires_field) {
    test += ` with ${m.requires_field.field} = ${m.requires_field.one_of.join(' or ')}`
  }
  if (m.requires_path_containing && m.requires_path_containing.length > 0) {
    test += `${m.requires_field ? ',' : ''} from a path containing ${m.requires_path_containing.join(' or ')}`
  }
  return test
}

/**
 * The mobile source-type label (ROADMAP §1.4), beside the other chips. Four
 * states, and only one of them is an absence: `none_recognised`, which the
 * server sends only for a finished walk that produced records, and which names
 * what was looked for. `not_assessed` says why, a failed request says it
 * failed, and nothing here ever reads "no mobile evidence".
 */
function MobileKindBadge({
  row,
  response,
  error,
}: {
  row: SourceKindRow | undefined
  response: SourceKindsResponse | undefined
  error: Error | null
}) {
  if (error) {
    const text = `mobile label unavailable — the label request failed (${error.message}); this is not a statement about the source`
    return (
      <span className="badge badge-warn" title={text} aria-label={text}>
        mobile label unavailable
      </span>
    )
  }
  if (!response) return null
  if (!row) {
    const text =
      'mobile evidence not assessed — this source has no row in the label response'
    return (
      <span className="badge" title={text} aria-label={text}>
        mobile: not assessed
      </span>
    )
  }
  if (row.kinds.length > 0) {
    const kinds = row.kinds.map((k) => KIND_LABEL[k] ?? k).join(' + ')
    const caveat = row.not_assessed_reason
      ? ` Other kinds are not ruled out: ${row.not_assessed_reason}.`
      : ''
    const text = `mobile evidence: ${kinds} — ${basisSentence(row)}.${caveat} Read from the records the parsers wrote, never from the source's name.`
    return (
      <span className="badge badge-accent" title={text} aria-label={text}>
        {kinds}
      </span>
    )
  }
  if (row.label === 'none_recognised') {
    const looked = response.looked_for.map(markerTest).join('; ')
    const text = `no mobile marker recognised — the walk completed and no record under this source passed any of these tests: ${looked}. A record of one of these types that failed its field or path test (a Mac's PowerLog, say) may be there and was not counted. That is what was looked for, not everything a phone can leave.`
    return (
      <span className="badge" title={text} aria-label={text}>
        no mobile marker recognised
      </span>
    )
  }
  const text = `mobile evidence not assessed — ${row.not_assessed_reason ?? 'no reason was given'}`
  return (
    <span className="badge" title={text} aria-label={text}>
      mobile: not assessed
    </span>
  )
}

function SourceCard({
  caseId,
  source,
  kinds,
}: {
  caseId: string
  source: SourceStat
  kinds: {
    data: SourceKindsResponse | undefined
    error: Error | null
  }
}) {
  const diskQuery = useQuery({
    queryKey: ['case', caseId, 'disk-map', source.source_artifact_id],
    queryFn: () => getDiskMap(caseId, source.source_artifact_id),
    retry: false,
  })
  // The source's own record, for what the ingest stamped on it. An encrypted
  // image is recognised, recorded and never opened (LIVE-003): the markers go
  // on this artifact's metadata, the incompleteness census counts them, and the
  // report prints them — but this card, the triage examiner's actual first
  // screen, showed "apfs_encrypted.dmg — 0 artifacts" and nothing else, which
  // is the reading the bug was filed about. Keyed like every other artifact
  // fetch so the cache is shared with the artifact page rather than doubled.
  const recordQuery = useQuery({
    queryKey: ['artifact', caseId, source.source_artifact_id],
    queryFn: () => getArtifact(caseId, source.source_artifact_id),
    retry: false,
    staleTime: 60_000,
  })

  const metadata = recordQuery.data?.metadata
  const encrypted = metadata?.encrypted === true
  const encryptionFormat =
    typeof metadata?.encryption_format === 'string'
      ? metadata.encryption_format
      : null
  const stamps = readIncompleteness(metadata)

  const fsRegions =
    diskQuery.data?.regions.filter((r) => r.artifact_type === 'FileSystem') ?? []

  const acquisition = readAcquisition(source)
  const count = formatCount(source.artifact_count)

  return (
    <div className="dash-source-card">
      <div className="dash-source-head">
        <span className="dash-source-name">{source.name}</span>
        <span className="dash-source-count mono">{count} artifacts</span>
        {/* Next to the number, because it is the number it qualifies. */}
        <AcquisitionBadge acquisition={acquisition} />
        <ProcessingBadge state={source.processing_state} />
        <MobileKindBadge
          row={kinds.data?.sources.find(
            (r) => r.source_artifact_id === source.source_artifact_id,
          )}
          response={kinds.data}
          error={kinds.error}
        />
        {/* An interrupted/cancelled walk stamps the source `inventory_incomplete`
            with reason `ingest_interrupted`, which is exactly what the red
            ProcessingBadge above and its note already say. Showing the generic
            "incomplete" chip too would be two chips for one fact; the badge
            stays for every OTHER incompleteness (an encrypted volume, a capped
            listing) on a source whose walk did finish. */}
        {source.processing_state !== 'interrupted' &&
          source.processing_state !== 'cancelled' && (
            <IncompleteBadge metadata={metadata} />
          )}
        <Link
          className="dash-source-link"
          to={`/cases/${caseId}/files/${source.source_artifact_id}?view=tree`}
        >
          Browse file tree
        </Link>
      </div>
      {/* The server falls back to the UUID when its root-artifact walk produced
          no name. Left unsaid, a bare UUID reads as a source with no name
          rather than as a name this response did not fetch. */}
      {source.name_resolved === false && (
        <div className="dash-muted">
          This source&rsquo;s name could not be resolved from the case&rsquo;s
          root artifacts, so the row above shows its UUID. Its acquisition state
          comes off that same walk, so nothing on this card says whether an
          integrity baseline was recorded for it either &mdash; not that none
          was.
        </div>
      )}
      {/* The acquisition state in full, for the two states that change what the
          count means and for one this screen cannot interpret. `acquired` and
          `unrecorded` get the chip alone: neither qualifies the number, and a
          block of prose on every ordinary source teaches an examiner to skip
          the block on the source where it matters. */}
      {acquisition.kind === 'failed' && (
        <div
          className="error-note"
          role="note"
          aria-label={`${source.name} — acquisition failed`}
        >
          ⚠ No acquisition baseline. Séance could not compute this
          source&rsquo;s acquisition hash, so the case holds this exhibit and
          cannot vouch for it: nothing ties the {count} artifacts beside its
          name to a verified copy of the original. The recorded reason:{' '}
          {acquisition.error ?? 'not recorded'}. A zero here may mean the source
          could not be read at all rather than that it contained nothing.
        </div>
      )}
      {acquisition.kind === 'acquiring' && (
        <div
          className="warn-note"
          role="note"
          aria-label={`${source.name} — acquisition in progress`}
        >
          Acquisition still in progress. This source&rsquo;s acquisition hash is
          still running, so it has not finished being processed. The {count}{' '}
          artifacts beside its name is a figure taken mid-ingest, not a total: a
          zero here means &ldquo;not yet&rdquo;, not &ldquo;nothing
          found&rdquo;.
        </div>
      )}
      {acquisition.kind === 'unrecognised' && (
        <div
          className="warn-note"
          role="note"
          aria-label={`${source.name} — acquisition state not recognised`}
        >
          This source&rsquo;s acquisition state is recorded as{' '}
          <span className="mono">{acquisition.state}</span>, which this screen
          does not recognise, so it cannot say what that means for the {count}{' '}
          artifacts beside its name. Read the source&rsquo;s own record before
          relying on that number.
        </div>
      )}
      {(source.processing_state === 'interrupted' ||
        source.processing_state === 'cancelled') && (
        <div
          className="error-note"
          role="note"
          aria-label={`${source.name} — processing ${source.processing_state}`}
        >
          ⚠ Processing did not finish. The {count} artifacts beside this
          source&rsquo;s name are what had been recorded when it stopped, not
          what the source holds.{' '}
          {source.processing_note ??
            'The walk stopped before it ended; what it had not reached is absent from this case, not from the evidence.'}
        </div>
      )}
      {recordQuery.isError && (
        <div
          className="error-note"
          role="note"
          aria-label={`${source.name} — record unavailable`}
        >
          This source&rsquo;s own record could not be read (
          {recordQuery.error.message}), so anything stamped on it — encryption,
          incompleteness — is not shown on this card. The absence of those notes
          here is not a statement that it is complete.
        </div>
      )}
      {encrypted && (
        <div
          className="warn-note"
          role="note"
          aria-label={`${source.name} — encrypted`}
        >
          ⚠ Recorded but never opened. This source is encrypted (
          {encryptionFormat ?? 'format not recorded'}) and Séance holds no key
          for it, so no volume, no filesystem and no file was extracted from it.
          The count of {formatCount(source.artifact_count)} artifacts beside its
          name is a statement about access, not a statement about its content.
          {stamps.length > 0 && (
            <> The record says: {incompletenessSentence(stamps)}.</>
          )}
        </div>
      )}
      {diskQuery.isPending && <div className="dash-skel" style={{ height: 96 }} />}
      {/* A missing partition map used to reach a console warning and nothing
          else, so a failed request looked exactly like a source with no
          partitions on it. For an encrypted source it is not a failure at all:
          nothing could have been parsed, and the danger styling made the
          product look broken instead of making the evidence look unopened. */}
      {diskQuery.isError &&
        (encrypted ? (
          <div className="dash-muted">
            No partition map — this source was never decrypted, so nothing was
            parsed from it. The server said: {diskQuery.error.message}.
          </div>
        ) : (
          <div className="error-note" role="note">
            Partition map unavailable: {diskQuery.error.message}. Nothing here
            says this source has no partitions.
          </div>
        ))}
      {diskQuery.data && <DiskMap caseId={caseId} data={diskQuery.data} />}
      {fsRegions.map((fs) => (
        <FsUsage key={fs.artifact_id} caseId={caseId} region={fs} />
      ))}
    </div>
  )
}

export function SourcesSection({ caseId }: { caseId: string }) {
  const sourcesQuery = useQuery({
    queryKey: ['case', caseId, 'stats', 'sources'],
    queryFn: () => getSourceStats(caseId),
    retry: false,
  })
  // Its own key and no polling: the label lists marker records and walks each
  // to its root, which the source counts must never wait for. The key carries
  // each source's walk state as the counts report it, so a label read while a
  // walk ran is re-read the moment the counts say the walk ended — "its walk is
  // still running" must never sit beside a ProcessingBadge that says it ended.
  const walkStates = (sourcesQuery.data?.sources ?? [])
    .map((s) => `${s.source_artifact_id}:${s.processing_state ?? ''}`)
    .join(',')
  const kindsQuery = useQuery({
    queryKey: ['case', caseId, 'source-kinds', walkStates],
    queryFn: () => getSourceKinds(caseId),
    retry: false,
    staleTime: 60_000,
  })

  return (
    <div className="panel">
      <h2 className="panel-title">Evidence sources</h2>
      {sourcesQuery.isPending && <div className="dash-skel" style={{ height: 120 }} />}
      {/* The panel stays and says why it is empty. Removing it made a transient
          API failure read as "this case has no evidence sources", which an
          examiner can take for a fact about the case (B8-021). */}
      {sourcesQuery.isError && (
        <div className="error-note" role="note">
          Evidence sources unavailable: {sourcesQuery.error.message}
        </div>
      )}
      {/* The disclosure on this response is about the NAMES: the counts come
          from a complete aggregate query, while the names come from a paged
          walk of the case's root artifacts that can be capped or meet rows that
          will not decode. Saying which is which keeps the note from reading as
          doubt about the artifact counts. */}
      {sourcesQuery.data?.inventory_incomplete && (
        <div
          className="warn-note"
          role="note"
          aria-label="Source names incomplete"
        >
          The walk over this case&rsquo;s root artifacts was short (
          {incompleteReasonLabel(
            sourcesQuery.data.inventory_incomplete_reason ?? null,
          )}
          {sourcesQuery.data.undecodable
            ? `; ${formatCount(sourcesQuery.data.undecodable)} root rows could not be decoded`
            : ''}
          ), so a source below may show a UUID instead of its name. The artifact
          counts come from their own complete query and are not affected.
        </div>
      )}
      {sourcesQuery.data &&
        (sourcesQuery.data.sources.length === 0 ? (
          <div className="dash-muted">No evidence sources.</div>
        ) : (
          sourcesQuery.data.sources.map((source) => (
            <SourceCard
              key={source.source_artifact_id}
              caseId={caseId}
              source={source}
              kinds={{ data: kindsQuery.data, error: kindsQuery.error }}
            />
          ))
        ))}
    </div>
  )
}
