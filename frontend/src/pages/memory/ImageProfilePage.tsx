import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import { SkeletonList } from '../../components/Skeleton'
import { formatBytes, formatCount } from '../../lib/format'
import {
  getMemoryCoverage,
  getMemoryProfile,
  type GradedFact,
  type MemoryCoverageResponse,
  type MemoryProfileResponse,
  type StageStatus,
} from './api'
import { useMemoryContext } from './memoryContext'
import { DegradedModePanel } from './DegradedModePanel'
import { EvidenceBadge, SymbolStatusBanner } from './confidence'
import {
  blobBool,
  blobNumber,
  blobString,
  blobStrings,
  failureSummary,
  filetimeText,
  readSymbolState,
  toHex,
} from './normalize'

/**
 * The image profile: where the honesty in this section lives.
 *
 * Four things are stated and never elided — the capture, the facts the address
 * translation rests on **with how each was established**, the symbol table, and
 * which analysis stages actually ran. An examiner reading a process list needs
 * to be able to come here and see what that list rests on: whether the
 * directory table base was read out of the crash-dump header or was the best of
 * nine scan candidates, and whether the symbol table proved anything at all.
 *
 * A wrong answer here looks like a page that shows a DTB with no grade, or that
 * lists a stage as run when it was skipped. Either lets an examiner treat an
 * incomplete analysis as a complete one.
 */

const STATUS_TONE: Record<StageStatus, string> = {
  complete: 'badge badge-ok',
  incomplete: 'badge badge-accent',
  failed: 'badge badge-danger',
  did_not_run: 'badge badge-danger',
  not_determined: 'badge badge-warn',
}

const FACT_LABEL: Record<string, string> = {
  directory_table_base: 'directory table base',
  kernel_base: 'kernel base',
  kdbg: 'KdDebuggerDataBlock',
}

export function ImageProfilePage() {
  const { caseId, imageId, image, scopeKey } = useMemoryContext()

  const profileQuery = useEntityScopedQuery<MemoryProfileResponse>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'profile'],
    queryFn: () => getMemoryProfile(caseId, imageId),
    retry: false,
  })
  const coverageQuery = useEntityScopedQuery<MemoryCoverageResponse>(scopeKey, {
    queryKey: ['memory', caseId, imageId, 'coverage'],
    queryFn: () => getMemoryCoverage(caseId, imageId),
    retry: false,
  })

  if (profileQuery.isPending || profileQuery.stale) {
    return <SkeletonList rows={10} label="Loading the capture profile" />
  }

  if (profileQuery.isError || profileQuery.scoped == null) {
    return (
      <div className="error-note" role="note">
        <strong>The capture profile could not be loaded.</strong> This is a load
        error, not a statement that the capture could not be profiled — those are
        different, and only the server can tell you which applies.
      </div>
    )
  }

  const data = profileQuery.scoped
  const profile = data.profile
  const coverage = coverageQuery.scoped
  const symbolState = readSymbolState(profile?.symbols_state)
  // A hibernation file is reconstructed into an ordinary memory image, but it
  // still carries header facts — whether an image is still in the file, and the
  // moment the machine wrote it — that exist in no other artifact and belong on
  // the profile alongside the analysis of its reconstructed pages.
  const hibernationRaw = data.image.hibernation
  const hibernation =
    hibernationRaw != null &&
    typeof hibernationRaw === 'object' &&
    !Array.isArray(hibernationRaw)
      ? (hibernationRaw as Record<string, unknown>)
      : null

  return (
    <div className="mem-profile">
      <section className="panel" aria-labelledby="mem-acq">
        <h2 className="panel-title" id="mem-acq">
          Acquisition
        </h2>
        <dl className="mem-kv">
          <div className="mem-kv-row">
            <dt>file</dt>
            <dd className="mono">{image.name ?? image.image_id}</dd>
          </div>
          <div className="mem-kv-row">
            <dt>format</dt>
            <dd className="mono">{image.image_format ?? 'not determined'}</dd>
          </div>
          <div className="mem-kv-row">
            <dt>architecture</dt>
            <dd className="mono">{image.architecture ?? 'not established'}</dd>
          </div>
          <div className="mem-kv-row">
            <dt>file bytes</dt>
            <dd>{formatBytes(image.file_bytes)}</dd>
          </div>
          <div className="mem-kv-row">
            <dt>addressable</dt>
            <dd>
              {formatBytes(image.addressable_bytes)}
              {image.declared_size != null && (
                <span className="mem-note">
                  {' '}
                  container declares {formatBytes(image.declared_size)}
                </span>
              )}
            </dd>
          </div>
          <div className="mem-kv-row">
            <dt>content complete</dt>
            <dd>
              {!image.content_complete_known ? (
                <>
                  <span className="badge badge-warn">not stated</span>
                  <span className="mem-note">
                    {' '}
                    The container did not say whether it holds everything it
                    declares. That is not the same as complete.
                  </span>
                </>
              ) : image.content_complete ? (
                <span className="badge badge-ok">declared complete</span>
              ) : (
                <>
                  <span className="badge badge-danger">declared incomplete</span>
                  <span className="mem-note">
                    {' '}
                    Part of what this capture declares is not in it. Anything
                    that lived there is missing, not zero.
                  </span>
                </>
              )}
            </dd>
          </div>
          {image.size_mismatch && (
            <div className="mem-kv-row">
              <dt>size</dt>
              <dd>
                <span className="badge badge-danger">mismatch</span>
                <span className="mem-note">
                  {' '}
                  The file on disk is not the size the container declares.
                </span>
              </dd>
            </div>
          )}
          {image.decode_failed && (
            <div className="mem-kv-row">
              <dt>decode</dt>
              <dd>
                <span className="badge badge-danger">failed</span>
                <span className="mem-note">
                  {' '}
                  The container could not be decoded, so nothing below rests on
                  a readable address space.
                </span>
              </dd>
            </div>
          )}
        </dl>
        <p className="mem-note">{image.analysis_state_meaning}</p>
      </section>

      {hibernation != null && <HibernationPanel facts={hibernation} />}

      <section className="panel" aria-labelledby="mem-evidence">
        <h2 className="panel-title" id="mem-evidence">
          What the analysis rests on
        </h2>
        {data.evidence == null ? (
          <p className="mem-note">
            No profile was established for this capture, so there are no graded
            facts to show. Grading facts that do not exist would put evidence
            labels on nothing.
          </p>
        ) : (
          <>
            <p className="mem-note">{data.evidence.note}</p>
            <dl className="mem-kv">
              {data.evidence.facts.map((fact) => (
                <FactRow key={fact.fact} fact={fact} />
              ))}
              <div className="mem-kv-row">
                <dt>weakest grade</dt>
                <dd>
                  <EvidenceBadge grade={data.evidence.weakest_evidence} />
                  <span className="mem-note">
                    {' '}
                    Every finding from this capture is at most this strong.
                  </span>
                </dd>
              </div>
            </dl>
            {data.evidence.ungraded_facts > 0 && (
              <div className="warn-note" role="note">
                <strong>
                  Ungraded facts: {data.evidence.ungraded_facts}.
                </strong>{' '}
                A fact that is present but carries no grade has not been
                confirmed by anything, and must not be read as if it had.
              </div>
            )}
          </>
        )}
      </section>

      {profile != null && (
        <section className="panel" aria-labelledby="mem-build">
          <h2 className="panel-title" id="mem-build">
            Kernel build and symbols
          </h2>
          <SymbolStatusBanner state={symbolState} />
          <dl className="mem-kv">
            <div className="mem-kv-row">
              <dt>build</dt>
              <dd className="mono">
                {blobNumber(profile, 'nt_major') ?? '?'}.
                {blobNumber(profile, 'nt_minor') ?? '?'} build{' '}
                {blobNumber(profile, 'nt_build') ?? 'not established'}
              </dd>
            </div>
            <div className="mem-kv-row">
              <dt>build stated by</dt>
              <dd className="mono">
                {blobString(profile, 'nt_build_source') ??
                  'no structure stated it'}
              </dd>
            </div>
            <div className="mem-kv-row">
              <dt>build lab</dt>
              <dd className="mono">
                {blobString(profile, 'build_lab') ?? 'not readable'}
              </dd>
            </div>
            <div className="mem-kv-row">
              <dt>PDB</dt>
              <dd className="mono">
                {blobString(profile, 'pdb') ?? '—'}
                {blobString(profile, 'pdb_guid')
                  ? ` | ${blobString(profile, 'pdb_guid')}`
                  : ''}
                {blobNumber(profile, 'pdb_age') != null
                  ? ` | age ${blobNumber(profile, 'pdb_age')}`
                  : ''}
              </dd>
            </div>
            <div className="mem-kv-row">
              <dt>architecture</dt>
              <dd className="mono">
                {blobString(profile, 'architecture') ?? 'not stated'} · pointer{' '}
                {blobNumber(profile, 'pointer_size') ?? '?'} bytes
              </dd>
            </div>
          </dl>
        </section>
      )}

      <section className="panel" aria-labelledby="mem-coverage">
        <h2 className="panel-title" id="mem-coverage">
          Which stages ran
        </h2>
        {coverageQuery.isPending || coverageQuery.stale ? (
          <SkeletonList rows={4} label="Loading stage coverage" />
        ) : coverageQuery.isError || coverage == null ? (
          <div className="error-note" role="note">
            Stage coverage could not be loaded. Without it there is no way to
            tell which lenses are empty because nothing was found and which are
            empty because nothing ran.
          </div>
        ) : (
          <>
            <p className="mem-note">{coverage.note}</p>
            <p className="mem-note">
              {coverage.summary.complete} complete ·{' '}
              {coverage.summary.incomplete} incomplete ·{' '}
              {coverage.summary.failed} failed ·{' '}
              {coverage.summary.did_not_run} did not run · of{' '}
              {coverage.summary.total_stages} stages
            </p>
            {!coverage.coverage_complete && (
              <div className="warn-note" role="note">
                The failure list itself was truncated, so this table may
                understate what did not run.
              </div>
            )}
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">status</th>
                  <th scope="col">stage</th>
                  <th scope="col">records</th>
                  <th scope="col">what it tells you</th>
                </tr>
              </thead>
              <tbody>
                {coverage.stages.map((stage) => (
                  <tr key={stage.stage}>
                    <td>
                      <span
                        className={STATUS_TONE[stage.status]}
                        title={stage.status_meaning}
                      >
                        {stage.status.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="mono">{stage.stage}</td>
                    <td>
                      {formatCount(stage.record_count)}
                      {stage.count_is_floor && (
                        <span className="badge badge-warn">floor</span>
                      )}
                    </td>
                    <td>
                      <span className="mem-note">{stage.describes}</span>
                      {stage.failures.length > 0 && (
                        <div className="mem-note">
                          {failureSummary(stage.failures)}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {coverage.unattributed_failures.length > 0 && (
              <div className="warn-note" role="note">
                <strong>
                  Failures naming a stage this build does not know about:
                </strong>{' '}
                {failureSummary(coverage.unattributed_failures)}. They are
                listed rather than dropped — an unrecognised stage that did not
                run is still a stage that did not run.
              </div>
            )}
          </>
        )}
      </section>

      {!data.profile_established && (
        <DegradedModePanel
          caseId={caseId}
          failure={data.failure ?? null}
          symbolDirs={
            Array.isArray(data.symbol_dirs_searched)
              ? data.symbol_dirs_searched
              : blobStrings(profile, 'symbol_dirs_searched')
          }
          identified={[
            { label: 'format', value: image.image_format ?? 'not determined' },
            {
              label: 'architecture',
              value: image.architecture ?? 'not established',
            },
            {
              label: 'addressable',
              value: formatBytes(image.addressable_bytes),
            },
          ]}
        />
      )}
    </div>
  )
}

/**
 * What a hibernation file's header states, alongside its reconstructed image.
 *
 * `hiberfil.sys` is a capture the machine took of itself. Séance reconstructs
 * its physical memory (Windows 10/11 x64 restore sets, Xpress-decompressed) and
 * analyses it like any other image — but the header still carries facts that
 * exist in no other artifact: whether an image is still present in the file and
 * the exact moment the machine wrote it, a timeline fact available nowhere else.
 * This panel surfaces them next to the analysis of the reconstructed pages.
 * Mirrors `hibernation_facts` in `seance_memory/src/module.rs`.
 */
function HibernationPanel({ facts }: { facts: Record<string, unknown> }) {
  const recognised = blobBool(facts, 'header_recognised')
  const mayHoldAnImage = blobBool(facts, 'may_hold_an_image')

  // No header was recognised, so there are no header facts. Drawing the table
  // below would put "state: not stated, page size: not stated" under a heading
  // that says these are the facts the header states — a row of absences read as
  // a reading of a file that was never read.
  if (recognised === false) {
    return (
      <section className="panel" aria-labelledby="mem-hibernation">
        <h2 className="panel-title" id="mem-hibernation">
          Hibernation file
        </h2>
        <div className="error-note" role="note">
          <strong>These bytes are not a hibernation header.</strong>{' '}
          {blobString(facts, 'detail') ??
            'The producer did not say what it read instead.'}{' '}
          {blobNumber(facts, 'bytes_read') != null && (
            <span className="mem-note">
              {blobNumber(facts, 'bytes_read')} bytes were read.
            </span>
          )}
        </div>
        <p className="mem-note">
          Nothing was read from this file as a hibernation image, so no state,
          time or page size is stated below or anywhere else.
        </p>
      </section>
    )
  }

  return (
    <section className="panel" aria-labelledby="mem-hibernation">
      <h2 className="panel-title" id="mem-hibernation">
        Hibernation file
      </h2>

      {recognised == null ? (
        <div className="warn-note" role="note">
          The record does not say whether the header was recognised, so nothing
          below can be read as established.
        </div>
      ) : null}

      <dl className="mem-kv">
        <div className="mem-kv-row">
          <dt>state</dt>
          <dd>
            <span className="mono">{blobString(facts, 'state') ?? 'not stated'}</span>
            <span className="mem-note">
              {' '}
              {blobString(facts, 'state_detail') ??
                'The producer recorded no explanation of this state.'}
            </span>
          </dd>
        </div>
        <div className="mem-kv-row">
          <dt>still holds an image</dt>
          <dd>
            {mayHoldAnImage == null ? (
              <span className="badge badge-warn">not stated</span>
            ) : mayHoldAnImage ? (
              <>
                <span className="badge badge-accent">yes</span>
                <span className="mem-note">
                  {' '}
                  Windows marks this file on resume rather than clearing it, so
                  the pages are normally still present.
                </span>
              </>
            ) : (
              <span className="badge badge-warn">no</span>
            )}
          </dd>
        </div>
        <div className="mem-kv-row">
          <dt>written at</dt>
          <dd className="mono">
            {filetimeText(blobNumber(facts, 'system_time_filetime'))}
          </dd>
        </div>
        <div className="mem-kv-row">
          <dt>page size</dt>
          <dd className="mono">
            {blobNumber(facts, 'page_size') ?? 'not stated'}
          </dd>
        </div>
        <div className="mem-kv-row">
          <dt>pages stored</dt>
          <dd className="mono">
            {blobNumber(facts, 'pages_stored') ?? 'not stated'}
          </dd>
        </div>
      </dl>

      <p className="mem-note">
        These are the facts the header states. The pages themselves are
        decompressed (both plain Xpress and Xpress-Huffman) and reconstructed
        into a physical address space, so this file is analysed like any other
        memory image. A block that does not decode, and older (Windows 7 and
        earlier) layouts, are reported as stated gaps rather than guessed.
      </p>
    </section>
  )
}

/**
 * One graded fact.
 *
 * A fact that is present but ungraded gets an explicit badge, never a blank —
 * an examiner must be able to see the difference between a value nobody checked
 * and one that was confirmed.
 */
function FactRow({ fact }: { fact: GradedFact }) {
  const label = FACT_LABEL[fact.fact] ?? fact.fact.replace(/_/g, ' ')
  if (!fact.present) {
    return (
      <div className="mem-kv-row">
        <dt>{label}</dt>
        <dd>
          <span className="badge badge-warn">not established</span>
          <span className="mem-note">
            {' '}
            The analysis did not find this. Nothing that needs it can be relied
            on.
          </span>
        </dd>
      </div>
    )
  }
  const numeric = typeof fact.value === 'number' ? fact.value : null
  const shown =
    numeric != null ? (toHex(numeric) ?? String(numeric)) : String(fact.value)
  return (
    <div className="mem-kv-row">
      <dt>{label}</dt>
      <dd>
        <span className="mono">{shown}</span> <EvidenceBadge grade={fact.evidence} />
      </dd>
    </div>
  )
}
