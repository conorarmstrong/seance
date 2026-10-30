import { useMemo } from 'react'
import {
  incompleteReasonLabel,
  incompletenessSentence,
  isSuperseded,
  readIncompleteness,
  summarizeIncompleteness,
  supersededBy,
  SCOPE_LABEL,
  SCOPE_MEANING,
  type HasMetadata,
  type IncompletenessSummary,
} from '../lib/incompleteness'
import { formatCount } from '../lib/format'

/**
 * The one way the standard incompleteness pair reaches an examiner.
 *
 * The plugin tree stamps `content_incomplete` / `content_incomplete_reason` and
 * `inventory_incomplete` / `inventory_incomplete_reason` wherever a result is
 * short. Those stamps exist for the person reading the screen, so every surface
 * that shows artifact-derived records renders them through this banner or this
 * badge, in the same words, with the reason named. A page that showed its own
 * phrasing would leave an examiner comparing two listings unable to tell
 * whether they were told the same thing.
 *
 * These deliberately reuse the `warn-note` / `badge badge-warn` tone already in
 * use for "we could not determine this", which is neither a pass nor a failure.
 */

/**
 * Aggregate the pair over a set of records.
 *
 * Memoized on the array identity, which is what every caller already holds:
 * a react-query page array, or a `useMemo`d flatMap of several.
 */
export function useIncompleteness(
  records: HasMetadata[] | null | undefined,
): IncompletenessSummary {
  return useMemo(() => summarizeIncompleteness(records), [records])
}

/**
 * The banner over a listing: how many of the records shown are short, and why.
 *
 * Renders nothing when nothing is stamped — an examiner must not learn to
 * ignore a banner that is always there. `noun` names what the records are so
 * the sentence reads as the page does ("images", "events", "messages").
 */
export function IncompletenessBanner({
  summary,
  noun = 'records',
  scopeNote,
}: {
  summary: IncompletenessSummary
  noun?: string
  /** Extra clause about which records were inspected, when it is not all of them. */
  scopeNote?: string
}) {
  if (summary.affected === 0) {
    // Nothing here is still short — but if something was, and a later run
    // answered it, that is worth one line rather than silence.
    return summary.superseded > 0 ? (
      <SupersededNote count={summary.superseded} noun={noun} />
    ) : null
  }
  return (
    <div className="warn-note incomplete-note" role="note">
      <p className="incomplete-lede">
        {formatCount(summary.affected)} of the{' '}
        {formatCount(summary.examined)} {noun} here{' '}
        {summary.affected === 1 ? 'declares itself' : 'declare themselves'}{' '}
        incomplete: what was parsed is not all there was.
        {scopeNote ? ` ${scopeNote}` : ''} Treat every count and every absence
        below as a floor, not a finding.
      </p>
      {summary.superseded > 0 ? (
        <p className="incomplete-lede superseded-line">
          A further {formatCount(summary.superseded)} {noun} recorded a
          shortfall that a later run answered; they are not counted above.
        </p>
      ) : null}
      <ul className="incomplete-reasons">
        {summary.tallies.map((tally) => (
          <li key={`${tally.scope}:${tally.reason ?? ''}`}>
            <span className="badge badge-warn" title={SCOPE_MEANING[tally.scope]}>
              {SCOPE_LABEL[tally.scope]}
            </span>{' '}
            <span>{incompleteReasonLabel(tally.reason)}</span>{' '}
            <span className="incomplete-count">
              ({formatCount(tally.count)}{' '}
              {tally.count === 1 ? 'record' : 'records'})
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/**
 * The one line a listing shows when nothing in it is still short, but something
 * in it was and a later run answered it.
 */
function SupersededNote({ count, noun }: { count: number; noun: string }) {
  return (
    <div className="superseded-note" role="note">
      <p className="incomplete-lede">
        <span className="badge">superseded</span> {formatCount(count)} {noun}{' '}
        here recorded a shortfall that a later run answered: what they reported
        as missing was subsequently recovered, and they are not counted as
        incomplete.
      </p>
    </div>
  )
}

/**
 * The banner for a single artifact, read straight off its metadata.
 *
 * Used where the examiner is looking at one record rather than a listing — a
 * file's detail pane, an artifact page — so the wording is about this thing
 * rather than about a proportion.
 */
export function ArtifactIncompleteness({
  metadata,
}: {
  metadata: Record<string, unknown> | null | undefined
}) {
  const stamps = readIncompleteness(metadata)
  if (stamps.length === 0) return null
  if (isSuperseded(metadata)) {
    // The record still says what it said, and it is still shown — but as
    // history, not as a live shortfall. Warning about missing data the case has
    // since recovered sends an examiner looking for something that is here.
    return (
      <div className="superseded-note" role="note">
        <p className="incomplete-lede">
          <span className="badge">superseded</span> This record describes the
          state before a later run answered it: what it reports as missing was
          subsequently recovered, and it is not counted among this case&rsquo;s
          incomplete results.
          {supersededBy(metadata) ? (
            <>
              {' '}
              The later record is{' '}
              <span className="mono">{supersededBy(metadata)}</span>.
            </>
          ) : null}
        </p>
        <ul className="incomplete-reasons">
          {stamps.map((stamp) => (
            <li key={stamp.scope}>
              <span className="badge">{SCOPE_LABEL[stamp.scope]}</span>{' '}
              <span>
                was recorded as{' '}
                <span className="mono">{stamp.reason ?? 'not recorded'}</span>
                {(stamp.additionalReasons ?? []).map((reason) => (
                  <span key={reason}>
                    {' '}
                    and <span className="mono">{reason}</span>
                  </span>
                ))}
                {stamp.detail ? `: ${stamp.detail}` : ''}
              </span>
            </li>
          ))}
        </ul>
      </div>
    )
  }
  return (
    <div className="warn-note incomplete-note" role="note">
      <ul className="incomplete-reasons">
        {stamps.map((stamp) => (
          <li key={stamp.scope}>
            <span className="badge badge-warn">{SCOPE_LABEL[stamp.scope]}</span>{' '}
            <span>
              {SCOPE_MEANING[stamp.scope]} The parser gave the reason as{' '}
              <span className="mono">{stamp.reason ?? 'not recorded'}</span>:{' '}
              {incompleteReasonLabel(stamp.reason)}.
              {/* Every further reason the record listed (UI-042): a second
                  cause is a second thing to follow up, not a footnote. */}
              {(stamp.additionalReasons ?? []).map((reason) => (
                <span key={reason}>
                  {' '}
                  It also gave <span className="mono">{reason}</span>:{' '}
                  {incompleteReasonLabel(reason)}.
                </span>
              ))}
              {/* The parser's own sentence, where it wrote one. It is the only
                  part of the stamp that can describe this record rather than
                  its category, so it is never summarised away. */}
              {stamp.detail ? ` ${stamp.detail}` : ''}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/**
 * The banner's content as one chip, for a toolbar that has no room for a block.
 *
 * Same numbers, same reasons, same words as `IncompletenessBanner` — carried in
 * the `title` and the accessible name so a page laid out as a strip of chips
 * (the gallery) reports the pair rather than skipping it for want of space.
 */
export function IncompletenessChip({
  summary,
  noun = 'records',
}: {
  summary: IncompletenessSummary
  noun?: string
}) {
  if (summary.affected === 0) return null
  const reasons = summary.tallies
    .map(
      (tally) =>
        `${SCOPE_LABEL[tally.scope]}: ${incompleteReasonLabel(tally.reason)} (${formatCount(tally.count)})`,
    )
    .join('; ')
  const verb =
    summary.affected === 1 ? 'declares itself' : 'declare themselves'
  const sentence =
    `${formatCount(summary.affected)} of the ${formatCount(summary.examined)} ${noun} loaded here ${verb} incomplete, so what is shown is a floor, not a finding. ` +
    reasons
  // The global badge tone, not the gallery's own `gl-warn`: the point of
  // routing every surface through this file is that one signal means one thing
  // wherever an examiner meets it.
  return (
    <span
      className="badge badge-warn incomplete-badge"
      role="note"
      title={sentence}
      aria-label={sentence}
    >
      ⚠ {formatCount(summary.affected)} incomplete
    </span>
  )
}

/**
 * The inline chip, for a row or a toolbar with no room for a sentence.
 *
 * The reason lives in the `title` and the accessible name, never dropped: a
 * chip saying only "incomplete" tells an examiner something is wrong and
 * nothing about what to do next.
 */
export function IncompleteBadge({
  metadata,
}: {
  metadata?: Record<string, unknown> | null
}) {
  const stamps = readIncompleteness(metadata)
  if (stamps.length === 0) return null
  const sentence = incompletenessSentence(stamps)
  if (isSuperseded(metadata)) {
    // Neutral tone on purpose: this is not a warning any more. The reasons stay
    // in the accessible name, because what was once missing is still part of
    // the history of the case.
    const answered = `superseded — this record describes the state before a later run answered it: ${sentence}`
    return (
      <span
        className="badge incomplete-badge"
        role="note"
        title={answered}
        aria-label={answered}
      >
        superseded
      </span>
    )
  }
  return (
    <span
      className="badge badge-warn incomplete-badge"
      role="note"
      title={sentence}
      aria-label={`incomplete — ${sentence}`}
    >
      ⚠ incomplete
    </span>
  )
}
