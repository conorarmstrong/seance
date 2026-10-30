import { Link } from 'react-router-dom'
import { ConfidenceChip } from './confidence'
import { blobNumber, blobString, blobStrings, type StageRow } from './normalize'

/**
 * One tampering signal, rendered with the copy discipline built into the card.
 *
 * Two strings are mandatory. The **observation** says what was seen. The
 * **benign explanation** says what innocent behaviour would produce the same
 * observation. A detector that supplies only the first has produced an
 * accusation rather than a finding, and this card says so on screen instead of
 * quietly rendering a one-sided panel — a missing rebuttal is a defect in the
 * detector, and an examiner is entitled to see it.
 *
 * The vocabulary is deliberately "anomalous", "unexplained", "consistent with".
 * Séance never renders the word "malicious": a memory capture cannot establish
 * intent, and a tool that claims otherwise does not survive cross-examination.
 */

const SEVERITY_TONE: Record<string, string> = {
  critical: 'badge badge-danger',
  high: 'badge badge-danger',
  medium: 'badge badge-accent',
  low: 'badge',
  info: 'badge',
}

/** Sort order for a findings list: most severe first. */
export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

/** Severity of one signal, or `unrated` when the detector gave none. */
export function severityOf(row: StageRow): string {
  return (
    blobString(row.data, 'severity') ?? blobString(row.data, 'level') ?? 'unrated'
  )
}

export function FindingCard({
  row,
  caseId,
  imageId,
}: {
  row: StageRow
  caseId: string
  imageId: string
}) {
  const data = row.data
  const severity = severityOf(row)
  const title =
    blobString(data, 'title') ??
    blobString(data, 'name') ??
    blobString(data, 'signal') ??
    'Signal with no title'
  const why =
    blobString(data, 'why') ??
    blobString(data, 'explanation') ??
    blobString(data, 'detail') ??
    blobString(data, 'description')
  const notProof =
    blobString(data, 'not_proof') ??
    blobString(data, 'benign_explanation') ??
    blobString(data, 'caveat')
  // The signal itself says what was seen; WHICH PROCESS it was seen in is on
  // the record that carried it, because the analysis emits one tampering record
  // per process with its signals in an array inside. Read from the signal alone
  // every real finding was "subject: not stated" with no way back to the
  // process — the fixtures put the process on the signal, which the producer
  // never does.
  const subject =
    blobString(data, 'subject') ??
    blobString(data, 'process_name') ??
    blobString(data, 'image_file_name') ??
    blobString(row.record, 'subject') ??
    blobString(row.record, 'process_name') ??
    blobString(row.record, 'image_file_name')
  const pid = blobNumber(data, 'pid') ?? blobNumber(row.record, 'pid')
  const detector = blobString(data, 'detector') ?? blobString(data, 'check')
  const mitre = blobStrings(data, 'mitre')

  return (
    <article className="mem-finding" aria-labelledby={`finding-${row.key}`}>
      <header className="mem-finding-head">
        <span className={SEVERITY_TONE[severity] ?? 'badge badge-warn'}>
          {severity}
        </span>
        <h3 className="mem-finding-title" id={`finding-${row.key}`}>
          {title}
        </h3>
        {mitre.map((technique) => (
          <span className="badge mono" key={technique}>
            {technique}
          </span>
        ))}
      </header>

      <dl className="mem-finding-body">
        <div className="mem-kv-row">
          <dt>subject</dt>
          <dd className="mono">
            {subject ?? 'not stated'}
            {pid != null ? ` (pid ${pid})` : ''}
          </dd>
        </div>
        <div className="mem-kv-row">
          <dt>observation</dt>
          <dd>
            {why ?? (
              <span className="mem-missing-rebuttal">
                The detector recorded no description of what it saw. Nothing can
                be concluded from this row without opening the record it came
                from.
              </span>
            )}
          </dd>
        </div>
        <div className="mem-kv-row">
          <dt>not proof</dt>
          <dd>
            {notProof ?? (
              <span className="mem-missing-rebuttal">
                This detector supplied no benign explanation. Treat the
                observation as unexplained rather than as evidence of intent, and
                corroborate it before relying on it.
              </span>
            )}
          </dd>
        </div>
        <div className="mem-kv-row">
          <dt>detector</dt>
          <dd className="mono">{detector ?? 'not stated'}</dd>
        </div>
        <div className="mem-kv-row">
          <dt>confidence</dt>
          <dd>
            <ConfidenceChip
              confidence={row.confidence}
              provenance={[{ label: 'record', value: row.recordId }]}
            />
          </dd>
        </div>
      </dl>

      {pid != null && (
        <footer className="mem-finding-refs">
          <Link
            className="btn"
            to={`/cases/${caseId}/memory/processes?image=${encodeURIComponent(imageId)}&pid=${pid}`}
          >
            Open process {pid}
          </Link>
        </footer>
      )}
    </article>
  )
}
