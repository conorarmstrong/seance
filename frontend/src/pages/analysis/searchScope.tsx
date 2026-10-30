import type { ReactNode } from 'react'
import { formatCount } from '../../lib/format'

/**
 * The one `q_match` token this UI knows how to put into words. Anything else is
 * quoted verbatim rather than described: a sentence about ASCII case folding
 * over a server that had started folding Unicode would be a claim about a
 * search that never ran.
 */
const ASCII_SUBSTRING = 'ascii_case_insensitive_substring'

/**
 * What the Filter box just did, said in a sentence.
 *
 * The filter used to be a browser-side scan of the rows that happened to be
 * loaded, and the toolbar carried a warning to that effect: a term missing
 * there was not a term missing from the case. `GET /cases/:id/records` now
 * takes `q` and `q_keys`, the scan is gone, and that warning has gone with it —
 * a caveat that outlives the limitation it described teaches an examiner to
 * skip past caveats, which costs more than never having written one.
 *
 * What replaces it is not a softer version of the same warning. It is the
 * three facts that are true of the new search and that a screen quoted under
 * oath has to carry:
 *
 *  * The two populations. "312 shown" is unreadable on its own — 312 of what?
 *    The matching set and the type it was drawn from are both named.
 *  * How the match was made. SQLite's LIKE folds ASCII case and nothing else,
 *    so "STRASSE" finds "strasse" but "Straße" does not match "STRASSE" — on a
 *    German-language device that is the difference between a hit and a false
 *    absence, and the examiner cannot infer it from the result.
 *  * What could not be tested. Records whose metadata will not parse were
 *    neither matches nor established non-matches, and a match count that
 *    silently omits them is a completeness claim it cannot support.
 */
export function SearchScopeNote({
  term,
  keys,
  matching,
  typeTotal,
  unfilterable,
  match,
  noun,
  testId = 'rv-search-scope',
}: {
  /** The term as sent to the server. */
  term: string
  /** The metadata keys it was tested against. */
  keys: string[]
  /** Records in the whole type that matched. */
  matching: number
  /** The type's own population, ignoring the term. */
  typeTotal: number
  /**
   * Records the filter could not be evaluated against. `null` means the
   * question was never asked, which must never be rendered as 0.
   */
  unfilterable: number | null
  /** The server's own `q_match` token, or null when it published none. */
  match: string | null
  /** Plural noun for the records, e.g. "event log entries". */
  noun: string
  testId?: string
}): ReactNode {
  return (
    <p className="rv-note" role="note" data-testid={testId}>
      {formatCount(matching)} of the {formatCount(typeTotal)} {noun} in this
      case match &ldquo;{term}&rdquo; in {keys.join(', ')}. The search ran on
      the server over every record of this type, not over the rows on screen.
      {match === ASCII_SUBSTRING ? (
        <>
          {' '}
          Matching is ASCII case-insensitive substring: STRASSE finds strasse,
          but Stra&szlig;e does not match STRASSE.
        </>
      ) : match ? (
        <> The server reports it matched by &ldquo;{match}&rdquo;.</>
      ) : null}
      {unfilterable == null ? null : unfilterable > 0 ? (
        <>
          {' '}
          <strong>
            {formatCount(unfilterable)} record
            {unfilterable === 1 ? '' : 's'} could not be read
          </strong>{' '}
          and {unfilterable === 1 ? 'was' : 'were'} therefore neither a match
          nor a non-match. {unfilterable === 1 ? 'It is' : 'They are'} not in
          either count above.
        </>
      ) : (
        <> Every record of this type was readable and was tested.</>
      )}
    </p>
  )
}

/**
 * The stat tiles, the histogram and the frequency bars are still computed in
 * the browser over the rows loaded so far — the filter moved to the server, they
 * did not. On a type with more matching records than have been fetched, a bar
 * chart of the loaded slice presented as a ranking of the case is the same
 * false-population reading the filter caveat used to guard against, so it keeps
 * its own sentence. This is a different limitation from the one that was
 * deleted, and it is live.
 */
export function ChartScopeNote({
  loaded,
  total,
  noun,
  filtered,
  testId = 'rv-charts-scope',
}: {
  loaded: number
  /** The set the charts would have to cover: matching records when filtered. */
  total: number
  noun: string
  /** True when a term is applied, so `total` is the matching population. */
  filtered: boolean
  testId?: string
}): ReactNode {
  return (
    <p className="rv-note" role="note" data-testid={testId}>
      The stat tiles, the histogram and the bars are computed in this browser
      over the {formatCount(loaded)} {noun} loaded so far, not over all{' '}
      {formatCount(total)}{' '}
      {filtered ? `matching ${noun}.` : `${noun} in this case.`} They rank what
      has been fetched. Scrolling loads more.
    </p>
  )
}
