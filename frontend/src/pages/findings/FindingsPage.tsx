import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import {
  getFindings,
  type CrossViewStatus,
  type Finding,
  type FindingDetection,
} from '../../api/resources'
import { formatCount } from '../../lib/format'
import { pivotTarget } from '../../lib/pivotable'
import { PivotMono } from '../analysis/cells'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import './findings.css'

/**
 * The triage screen (ROADMAP §2.2): the jump from "2M parsed objects" to "the
 * things that look wrong, ranked, each with the evidence it rests on".
 *
 * # This screen is under an obligation the other screens are not
 *
 * Every other view here renders a **transcription** — the MFT said this, the
 * registry held that. Every row on this one is Séance's own claim that a
 * pattern deserves attention, and Part VI of `ROADMAP.md` forbids presenting
 * that as though the two were established the same way. Three things follow,
 * and none of them is decoration:
 *
 * * **The observation and the inference are rendered separately and labelled.**
 *   The observation is a fact an examiner or an opponent can check against the
 *   artifact it names. The inference is opinion. Merging them into one
 *   paragraph is exactly the failure the `Finding` type was shaped to prevent,
 *   and it would be undone here by a layout that read the two as one
 *   description.
 * * **The qualification is never collapsed behind a disclosure.** What a
 *   finding does *not* establish is part of the finding, not a footnote: a
 *   reader who sees only the claim has read half of it.
 * * **What this build cannot look for is on the screen.** An empty list means
 *   one of two completely different things — nothing matched the detections
 *   present, or nothing here looks for what the examiner is after — and while
 *   this layer is being built out the second is usually the truth.
 */
const CONFIDENCE_LABEL: Record<Finding['confidence'], string> = {
  strong: 'Strong',
  notable: 'Notable',
  weak: 'Weak',
}

/**
 * What each grade means, in the terms the scale was actually built on: how
 * much room there is for an innocent explanation. Shown as the chip's title so
 * "Weak" is not read as "probably nothing" or "Strong" as "established".
 */
const CONFIDENCE_TITLE: Record<Finding['confidence'], string> = {
  strong:
    'Hard to produce by ordinary use of the machine. Still a lead: "hard to produce innocently" is not "produced deliberately".',
  notable:
    'Unusual and worth explaining, but a legitimate cause is known and common.',
  weak: 'There is an ordinary explanation at least as likely as a suspicious one. Surfaced because it is cheap to check, not because it is probably wrong.',
}

const ORDER: Finding['confidence'][] = ['strong', 'notable', 'weak']

/** One lead. */
function FindingRow({ caseId, finding }: { caseId: string; finding: Finding }) {
  const [open, setOpen] = useState(false)
  return (
    <article className="fnd-card" data-testid="fnd-card">
      <header className="fnd-card-head">
        <span
          className={`badge fnd-conf fnd-conf-${finding.confidence}`}
          title={CONFIDENCE_TITLE[finding.confidence]}
        >
          {CONFIDENCE_LABEL[finding.confidence]}
        </span>
        <h3 className="fnd-title">{finding.name}</h3>
        <span className="fnd-kind mono" title={`Raised by ${finding.source_module}`}>
          {finding.finding_kind}
        </span>
      </header>

      {/* The observation, first and unqualified by any layout: this is the
          checkable half. */}
      <p className="fnd-observation">{finding.observation}</p>

      {/* The inference, labelled. `null` where the observation speaks for
          itself, and then nothing is shown rather than an empty heading — a
          reading invented to fill a slot is exactly what the split prevents. */}
      {finding.inference && (
        <p className="fnd-inference" data-testid="fnd-inference">
          <span className="fnd-label">What this may indicate — Séance's reading, not a fact:</span>{' '}
          {finding.inference}
        </p>
      )}

      {/* Never behind a disclosure. A reader who sees only the claim has read
          half the finding. */}
      <p className="fnd-qualification" data-testid="fnd-qualification">
        <span className="fnd-label">What it does not establish:</span>{' '}
        {finding.qualification}
      </p>

      <div className="fnd-actions">
        <Link
          className="fnd-open"
          to={`/cases/${caseId}/artifacts/${finding.subject_artifact_id}`}
        >
          Open the artifact this is about
        </Link>
        {finding.persisted && finding.artifact_id && (
          <Link
            className="fnd-open-secondary"
            to={`/cases/${caseId}/artifacts/${finding.artifact_id}`}
          >
            Open the finding record
          </Link>
        )}
        {finding.device_offset !== null && (
          <span className="fnd-offset mono" title="Byte offset on the backing device">
            offset {finding.device_offset}
          </span>
        )}
        <button
          type="button"
          className="fnd-evidence-toggle"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
        >
          {open ? 'Hide' : 'Show'} the {formatCount(finding.evidence.length)}{' '}
          value{finding.evidence.length === 1 ? '' : 's'} it rests on
        </button>
      </div>

      {open && (
        <dl className="fnd-evidence" data-testid="fnd-evidence">
          {finding.evidence.map((e, i) => {
            const target = pivotTarget(e.name, e.value)
            return (
              <div className="fnd-evidence-row" key={`${e.name}-${i}`}>
                <dt className="mono">{e.name}</dt>
                <dd className="mono">
                  {target ? <PivotMono pivotOn={target} /> : e.value}
                </dd>
              </div>
            )
          })}
        </dl>
      )}

      {/* A row that is not an artifact says so where it is read, not only in
          the header block: a reader citing this one has nothing to cite. */}
      {!finding.persisted && finding.not_persisted_note && (
        <p className="fnd-not-persisted" role="note" data-testid="fnd-not-persisted">
          {finding.not_persisted_note}
        </p>
      )}
    </article>
  )
}

/** What this build can look for at all. */
function Detections({ detections }: { detections: FindingDetection[] }) {
  const [open, setOpen] = useState(false)
  return (
    <section className="fnd-detections" data-testid="fnd-detections">
      <button
        type="button"
        className="fnd-detections-toggle"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        {open ? 'Hide' : 'Show'} the {formatCount(detections.length)} thing
        {detections.length === 1 ? '' : 's'} this build looks for
      </button>
      {open && (
        <dl className="fnd-detections-list">
          {detections.map((d) => (
            <div className="fnd-detection" key={`${d.kind}-${d.module}`}>
              <dt className="mono">{d.kind}</dt>
              <dd>
                {d.looks_for}{' '}
                <span className="fnd-detection-module mono">{d.module}</span>
              </dd>
            </div>
          ))}
        </dl>
      )}
    </section>
  )
}

/**
 * Whether the two whole-case detections ran, and what they covered.
 *
 * Always rendered, in all three states. "The cross-view checks ran and found
 * nothing" and "the cross-view checks could not be run" are different facts
 * about this case, and a screen that shows the first when the second is true
 * tells the examiner the machine is clean on a question nobody asked.
 */
function CrossView({ status }: { status: CrossViewStatus }) {
  if (!status.ran) {
    return (
      <p className="warn-note" role="note" data-testid="fnd-cross-view">
        The two checks that need the whole case at once — a program that ran
        with no file left behind, a journal delete the MFT contradicts — were
        not run. {status.declined}
      </p>
    )
  }
  if (!status.complete) {
    return (
      <p className="warn-note" role="note" data-testid="fnd-cross-view">
        The two whole-case checks ran against{' '}
        {formatCount(status.file_entries_compared_against)} file entries, but
        not over everything: {status.limits.join(' ')} Anything past those
        limits was not checked, and its absence from this list is not a finding.
      </p>
    )
  }
  return (
    <p className="fnd-sub" data-testid="fnd-cross-view">
      The two whole-case checks ran in full against{' '}
      {formatCount(status.file_entries_compared_against)} file{' '}
      {status.file_entries_compared_against === 1 ? 'entry' : 'entries'} and
      raised {formatCount(status.findings)}.
    </p>
  )
}

export function FindingsPage() {
  const { caseId } = useParams<{ caseId: string }>()
  // Scoped to the case: the page stays mounted across a `:caseId` change, and
  // a grade filter left on from case A would silently hide case B's leads.
  const [only, setOnly] = useEntityScopedState<Finding['confidence'] | 'all'>(
    caseId ?? '',
    'all',
  )
  const query = useQuery({
    queryKey: ['findings', caseId],
    queryFn: () => getFindings(caseId!),
    enabled: !!caseId,
  })

  const shown = useMemo(() => {
    const rows = query.data?.findings ?? []
    return only === 'all' ? rows : rows.filter((f) => f.confidence === only)
  }, [query.data, only])

  if (query.isPending) return <div className="loading">Ranking findings…</div>
  // A failed load must never render as an empty list: that is a statement
  // about the case.
  if (query.isError) {
    return (
      <div className="error-note" role="note">
        Findings unavailable: {(query.error as Error).message}. Nothing here
        says this case holds none.
      </div>
    )
  }
  const data = query.data
  if (!data) return null

  return (
    <div className="fnd">
      <header className="fnd-head">
        <h1>Findings</h1>
        <p className="fnd-sub">
          {formatCount(data.total)} investigative{' '}
          {data.total === 1 ? 'lead' : 'leads'}, most confident first
          {data.truncated
            ? ` — showing the first ${formatCount(data.listed)}`
            : ''}
          .
        </p>
        {/* The grade, once, at the top. Every row below is one of these and
            the screen says so before the reader starts reading rows. */}
        <p className="fnd-grade" role="note" data-testid="fnd-grade">
          {data.grade_note}
        </p>
        <CrossView status={data.cross_view} />
      </header>

      <Detections detections={data.detections} />

      {data.total === 0 ? (
        <div className="empty-state" data-testid="fnd-empty">
          <h3>No findings</h3>
          {/* The server's own sentence, which distinguishes "nothing matched"
              from "nothing here looks for that" and carries the cross-view
              outcome. Rewriting it here would let the two drift. */}
          <p>{data.absence_note}</p>
        </div>
      ) : (
        <>
          <div className="fnd-filter" role="group" aria-label="Filter by confidence">
            <button
              type="button"
              className={only === 'all' ? 'fnd-chip fnd-chip-on' : 'fnd-chip'}
              aria-pressed={only === 'all'}
              onClick={() => setOnly('all')}
            >
              All {formatCount(data.total)}
            </button>
            {ORDER.map((c) => (
              <button
                key={c}
                type="button"
                className={only === c ? 'fnd-chip fnd-chip-on' : 'fnd-chip'}
                aria-pressed={only === c}
                title={CONFIDENCE_TITLE[c]}
                onClick={() => setOnly(c)}
                disabled={(data.by_confidence[c] ?? 0) === 0}
              >
                {CONFIDENCE_LABEL[c]} {formatCount(data.by_confidence[c] ?? 0)}
              </button>
            ))}
          </div>

          {shown.length === 0 ? (
            // The chips are driven by `by_confidence`, so a chip with a count
            // above zero and no rows behind it means the counts and the list
            // disagree. Blaming the filter would be a fabricated explanation;
            // showing case-wide counts above an empty list would read as "no
            // findings in this case". The honest statement is the
            // disagreement itself.
            <div className="warn-note" role="note" data-testid="fnd-none-returned">
              This case reports {formatCount(data.by_confidence[only] ?? 0)}{' '}
              {only} {(data.by_confidence[only] ?? 0) === 1 ? 'lead' : 'leads'}{' '}
              and none came back to list. They are not shown here, and their
              absence from this page is not a finding that they do not exist.
              Clear the filter to see the {formatCount(data.total)} this case
              reports in total.
            </div>
          ) : (
            <div className="fnd-list">
              {shown.map((f, i) => (
                <FindingRow
                  key={f.artifact_id ?? `${f.finding_kind}-${f.name}-${i}`}
                  caseId={caseId!}
                  finding={f}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default FindingsPage
