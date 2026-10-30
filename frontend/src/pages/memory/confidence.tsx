import type { EvidenceGrade } from './api'
import {
  deriveConfidence,
  LEVEL_TONE,
  presenceFor,
  presenceLabel,
  type ConfidenceLevel,
  type ConfidenceVerdict,
  type CrossviewMethod,
  type CrossviewRow,
  type RecordConfidence,
  type SymbolState,
} from './normalize'

/**
 * The confidence chip, the evidence badge and the presence glyph.
 *
 * Every table of memory-derived rows carries the chip in its first column,
 * before the data, so an examiner never has to remember which enumeration a row
 * came from. The chip states the weakest of the confidence axes; opening it
 * names each axis and what it means for this row. A row graded `scanned` must
 * never look like one graded `linked`, and neither may look like `unreliable`.
 */

const LEVEL_SUMMARY: Record<ConfidenceLevel, string> = {
  linked:
    'Every axis is clean: a kernel structure walk, complete reads, verified symbols, a confirmed profile.',
  scanned:
    'Something here was scanned for rather than read from a kernel list, or rests on a profile fact nobody confirmed.',
  partial: 'Some bytes behind this row could not be read, or a cap was hit.',
  approximate:
    'The symbol table or the profile behind this row was never proved correct.',
  unreliable:
    'Nothing corroborates this row, or no admitted symbol table stands behind it.',
}

/** The chip alone, for places with no room for a popover. */
export function ConfidenceBadge({ verdict }: { verdict: ConfidenceVerdict }) {
  return (
    <span
      className={LEVEL_TONE[verdict.level]}
      aria-label={verdict.ariaLabel}
      title={LEVEL_SUMMARY[verdict.level]}
    >
      {verdict.level}
    </span>
  )
}

/**
 * The chip plus its "why is this row marked …" popover.
 *
 * Rendered as a native disclosure so it opens on `Enter` and is reachable by
 * keyboard without a focus trap, which matters inside a 400-row table.
 */
export function ConfidenceChip({
  confidence,
  provenance,
}: {
  confidence: RecordConfidence | null | undefined
  /** Extra provenance lines: struct, member, virtual and physical address. */
  provenance?: { label: string; value: string }[]
}) {
  const verdict = deriveConfidence(confidence)
  return (
    <details className="mem-conf">
      <summary
        className="mem-conf-summary"
        aria-label={`${verdict.ariaLabel}. Open for the reasons.`}
      >
        <ConfidenceBadge verdict={verdict} />
      </summary>
      <div className="mem-conf-pop" role="note">
        <h4 className="mem-conf-title">
          Why this row is marked &ldquo;{verdict.level}&rdquo;
        </h4>
        <p className="mem-conf-lede">{LEVEL_SUMMARY[verdict.level]}</p>
        <dl className="mem-conf-axes">
          {verdict.reasons.map((reason) => (
            <div className="mem-conf-axis" key={reason.axis}>
              <dt>{reason.axis}</dt>
              <dd>
                <span className="mem-conf-value mono">{reason.label}</span>
                <span className="mem-conf-detail">{reason.detail}</span>
              </dd>
            </div>
          ))}
          {provenance?.map((line) => (
            <div className="mem-conf-axis" key={line.label}>
              <dt>{line.label}</dt>
              <dd>
                <span className="mem-conf-value mono">{line.value}</span>
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </details>
  )
}

const EVIDENCE_TONE: Record<EvidenceGrade, string> = {
  confirmed: 'badge badge-ok',
  validated: 'badge badge-accent',
  scanned: 'badge badge-warn',
  supplied: 'badge badge-warn',
}

const EVIDENCE_MEANING: Record<EvidenceGrade, string> = {
  confirmed:
    'Read directly out of a kernel structure the image points at, then confirmed by using it.',
  validated:
    'Derived by scanning, then checked against something independent that agreed.',
  scanned:
    'Derived by scanning, with no independent check available. Nothing has confirmed it.',
  supplied: 'Supplied by the examiner rather than discovered from the image.',
}

/**
 * The grade behind one discovered fact: the DTB, the kernel base, the KDBG.
 *
 * An examiner has to be able to see what a finding rests on, so a value that
 * was scanned for and never checked must not carry the same badge as one the
 * kernel stated and that was then proved by using it. A grade the server did
 * not state renders as an explicit gap, never as a pass.
 */
export function EvidenceBadge({ grade }: { grade: EvidenceGrade | null }) {
  if (grade == null) {
    return (
      <span
        className="badge badge-danger"
        title="The server did not state how this value was established."
        aria-label="evidence grade not stated"
      >
        not stated
      </span>
    )
  }
  return (
    <span
      className={EVIDENCE_TONE[grade]}
      title={EVIDENCE_MEANING[grade]}
      aria-label={`evidence ${grade}: ${EVIDENCE_MEANING[grade]}`}
    >
      {grade}
    </span>
  )
}

const SYMBOL_COPY: Record<SymbolState, { tone: string; text: string }> = {
  verified: {
    tone: 'badge badge-ok',
    text: 'The symbol table passed every admission gate. Structure offsets come from it.',
  },
  unverified: {
    tone: 'badge badge-accent',
    text: 'The symbol table failed no gate, but nothing proved it either. Offsets are unconfirmed and every row decoded with them is graded approximate.',
  },
  rejected: {
    tone: 'badge badge-danger',
    text: 'A candidate symbol table failed an admission gate and was refused. Typed enumeration cannot run.',
  },
  no_match: {
    tone: 'badge badge-danger',
    text: 'No symbol table matched this kernel build. Typed enumeration cannot run.',
  },
}

/**
 * The symbol banner, shown wherever symbol state changes what a lens can mean.
 *
 * A state the server did not report is its own case: it is not verified, and it
 * is not a refusal either, so it says exactly that.
 */
export function SymbolStatusBanner({ state }: { state: SymbolState | null }) {
  if (state == null) {
    return (
      <p className="mem-symbol-banner" role="note">
        <span className="badge badge-warn">symbols not stated</span>{' '}
        <span>
          The profile did not report a symbol state. Nothing here should be read
          as verified, and nothing should be read as refused either — the
          question was not answered.
        </span>
      </p>
    )
  }
  const copy = SYMBOL_COPY[state]
  return (
    <p className="mem-symbol-banner" role="note">
      <span className={copy.tone}>symbols {state.replace('_', ' ')}</span>{' '}
      <span>{copy.text}</span>
    </p>
  )
}

/** Header cell for the confidence column, so every table labels it the same. */
export function ConfidenceHeader() {
  return (
    <th scope="col" className="mem-col-conf" title="How this row was established">
      Conf.
    </th>
  )
}

/**
 * The n-of-m presence glyph.
 *
 * One mark per enumeration strategy: filled when the strategy saw this row,
 * hollow when it ran and did not, and a question mark when it did not run. That
 * third state is the one that matters — a scanner that crashed says nothing
 * about whether a process is hidden, and rendering it as an absence would
 * manufacture the single most serious finding in memory forensics.
 */
export function AgreementGlyph({
  methods,
  row,
}: {
  methods: CrossviewMethod[]
  row: CrossviewRow | undefined
}) {
  if (methods.length === 0) {
    return (
      <span
        className="mem-glyph mem-glyph-none"
        aria-label="no enumeration strategies reported"
      >
        —
      </span>
    )
  }
  return (
    <span className="mem-glyph" aria-label={presenceLabel(methods, row)} role="img">
      {methods.map((method) => {
        const presence = presenceFor(method, row)
        const mark =
          presence === 'seen' ? '●' : presence === 'not_seen' ? '○' : '?'
        return (
          <span
            key={method.key}
            className={`mem-glyph-dot mem-glyph-${presence}`}
            aria-hidden="true"
          >
            {mark}
          </span>
        )
      })}
    </span>
  )
}
