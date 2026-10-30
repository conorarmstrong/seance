import { useMemo } from 'react'
import { useEntityScopedState } from '../lib/useEntityScopedState'
import { formatCount } from '../lib/format'
import './quickFilter.css'

/**
 * The quick type-ahead filter every grid gets (ROADMAP §1.1).
 *
 * Filter UX is the one weakness both Belkasoft reviewers named, and the gap was
 * not compound filters — those ship, with a library and import/export — but the
 * small thing: a box above a table that narrows it as you type. Two grids had
 * one each, written twice, and the other twenty did not.
 *
 * # The honesty rule this primitive exists to enforce
 *
 * A client-side type-ahead filters **what is loaded**, not the case. Every grid
 * in this product is paged, capped or windowed, so "3 matches" over a loaded
 * slice of a 40,000-row population is a statement about the slice — and a grid
 * that printed it bare would be telling an examiner there are three in the
 * case. That is the false-absence class this project treats as HIGH.
 *
 * So the count is never printed alone. [`QuickFilterBar`] states the population
 * it searched, and when the caller says that population is a subset
 * (`loadedIsSubset`) it says so in the same breath, in a sentence rather than a
 * badge: a filtered grid is read, quoted and screenshotted, and none of those
 * carry a hover.
 *
 * # Scoping
 *
 * The query is held per entity (usually the case) through
 * [`useEntityScopedState`], because a grid stays mounted across a `:caseId`
 * change and a needle from case A matches nothing in case B — the examiner is
 * then shown an empty grid for a case that has rows, with no visible reason
 * why (B2-092).
 */
export interface QuickFilterResult<T> {
  /** The needle, verbatim. */
  query: string
  setQuery: (q: string) => void
  /** The rows that matched, in the caller's order. */
  rows: T[]
  /** Whether a needle is set at all. */
  active: boolean
  /** Rows searched: the population the count above is out of. */
  searched: number
}

/**
 * Narrow `rows` by a type-ahead needle over the strings `fields` returns.
 *
 * Matching is case-insensitive substring over every field, which is what a
 * reader typing three characters expects. It is deliberately **not** fuzzy: a
 * fuzzy match in a grid an examiner is reading as a population would include
 * rows they cannot see the reason for, and a filter whose rule cannot be
 * stated is one whose result cannot be defended.
 *
 * `fields` may return `null`/`undefined` entries; they are skipped rather than
 * stringified, so a row with no name does not match the needle "null".
 */
export function useQuickFilter<T>(
  scopeId: string,
  rows: readonly T[],
  fields: (row: T) => readonly (string | null | undefined)[],
): QuickFilterResult<T> {
  const [query, setQuery] = useEntityScopedState<string>(scopeId, '')
  const needle = query.trim().toLowerCase()

  const filtered = useMemo(() => {
    if (needle === '') return rows as T[]
    return (rows as T[]).filter((row) =>
      fields(row).some(
        (value) =>
          typeof value === 'string' && value.toLowerCase().includes(needle),
      ),
    )
    // `fields` is a closure the caller re-creates each render; depending on it
    // would recompute on every render and defeat the memo. The rows and the
    // needle are what the result depends on.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, needle])

  return {
    query,
    setQuery,
    rows: filtered,
    active: needle !== '',
    searched: rows.length,
  }
}

/**
 * The input, and the sentence that stops its count being read as the case.
 *
 * `noun` names what the rows are, singular ("file entry", "event", "record"),
 * so the sentence reads as English rather than as a template. `plural` is
 * `noun + "s"` unless given — pass it for anything that does not pluralise
 * that way ("file entry" → "file entries"), because the label and the sentence
 * are both read by a person.
 *
 * `loadedIsSubset` is the caller's answer to "is the list you handed me the
 * whole population?". Pass `true` whenever the grid is paged, capped or
 * windowed and has not loaded everything — the bar then says the filter ran
 * over the loaded rows only. Passing `false` when it is not true is how a grid
 * comes to assert a population it does not have.
 */
export function QuickFilterBar<T>({
  filter,
  noun,
  plural: pluralProp,
  label,
  placeholder,
  loadedIsSubset = false,
  total,
  testId = 'quick-filter',
}: {
  filter: QuickFilterResult<T>
  noun: string
  /** Plural of `noun`. Defaults to `noun + "s"`. */
  plural?: string
  /** Accessible name for the input. Defaults to `Filter ${plural}`. */
  label?: string
  placeholder?: string
  loadedIsSubset?: boolean
  /** The case-wide population, where the caller knows it. */
  total?: number
  testId?: string
}) {
  const plural = pluralProp ?? `${noun}s`
  const name = label ?? `Filter ${plural}`
  return (
    <div className="qf" data-testid={testId}>
      <input
        className="qf-input"
        type="text"
        value={filter.query}
        aria-label={name}
        placeholder={placeholder ?? `Filter ${plural}…`}
        onChange={(e) => filter.setQuery(e.target.value)}
      />
      {filter.active && (
        <p className="qf-count" role="status" data-testid={`${testId}-count`}>
          {formatCount(filter.rows.length)} of{' '}
          {formatCount(filter.searched)} {filter.searched === 1 ? noun : plural}{' '}
          {filter.rows.length === 1 ? 'matches' : 'match'}
          {loadedIsSubset ? (
            <>
              {' '}
              — and those {formatCount(filter.searched)} are the{' '}
              <strong>loaded</strong> {plural}
              {total !== undefined && total > filter.searched
                ? ` of ${formatCount(total)} in this case`
                : ''}
              , not all of them. This filter did not search the rest, so a{' '}
              {noun} missing from the list below is not a {noun} the case does
              not hold.
            </>
          ) : (
            '.'
          )}
        </p>
      )}
    </div>
  )
}
