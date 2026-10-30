import {
  readScope,
  scopeSentence,
  scopeWord,
  type MeasuredScope,
  type ScopeSpec,
} from '../lib/measuredScope'

/**
 * The one way a figure's declared extent reaches an examiner.
 *
 * Renders nothing when the producer declared the figure whole, so a badge that
 * appears is always saying something. Where it does appear the reason travels
 * with it, in the `title` and the accessible name — a chip reading only
 * "sampled" tells an examiner the number is qualified and nothing about what
 * the qualification costs them.
 *
 * Tone follows `lib/incompleteness.ts`: `badge-warn` is this codebase's "we
 * could not stand behind this as stated", which is neither a pass nor a
 * failure.
 */
export function ScopeBadge({
  metadata,
  spec,
}: {
  metadata?: Record<string, unknown> | null
  spec: ScopeSpec
}) {
  const scope = readScope(metadata, spec)
  return <ScopeBadgeFor scope={scope} spec={spec} />
}

/** `ScopeBadge` for a scope the caller has already read. */
export function ScopeBadgeFor({
  scope,
  spec,
}: {
  scope: MeasuredScope
  spec: ScopeSpec
}) {
  if (scope.state === 'whole') return null
  const sentence = scopeSentence(scope, spec)
  const word = scopeWord(scope, spec)
  return (
    <span
      className="badge badge-warn incomplete-badge"
      role="note"
      title={sentence}
      aria-label={`${word} — ${sentence}`}
    >
      {word}
    </span>
  )
}

/**
 * The extent as a line of text under the figure, for a cell or panel that has
 * room for it. The badge alone puts the numbers behind a hover, and a printed
 * page or a screenshot has no hover.
 */
export function ScopeNote({
  metadata,
  spec,
}: {
  metadata?: Record<string, unknown> | null
  spec: ScopeSpec
}) {
  const scope = readScope(metadata, spec)
  if (scope.state === 'whole') return null
  return (
    <span className="scope-note" role="note">
      {scopeSentence(scope, spec)}
    </span>
  )
}
