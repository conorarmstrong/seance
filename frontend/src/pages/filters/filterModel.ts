/**
 * Filter-condition model shared with the backend `seance_core::filter`.
 * A condition is Simple (`field op value`), Compound (AND/OR of conditions), or
 * Not. This module builds a Simple condition from form input and renders any
 * condition as a human summary.
 */

export type FilterOp =
  | 'eq'
  | 'neq'
  | 'gt'
  | 'lt'
  | 'gte'
  | 'lte'
  | 'contains'
  | 'starts_with'
  | 'ends_with'
  | 'in'
  | 'exists'

export interface SimpleCondition {
  type: 'simple'
  field: string
  operator: FilterOp
  value: unknown
}
export interface CompoundCondition {
  type: 'compound'
  logic: 'and' | 'or'
  conditions: FilterCondition[]
}
export interface NotCondition {
  type: 'not'
  condition: FilterCondition
}
export type FilterCondition =
  | SimpleCondition
  | CompoundCondition
  | NotCondition

export const FILTER_OPS: { id: FilterOp; label: string }[] = [
  { id: 'eq', label: 'equals' },
  { id: 'neq', label: 'not equals' },
  { id: 'contains', label: 'contains' },
  { id: 'starts_with', label: 'starts with' },
  { id: 'ends_with', label: 'ends with' },
  { id: 'gt', label: '>' },
  { id: 'gte', label: '>=' },
  { id: 'lt', label: '<' },
  { id: 'lte', label: '<=' },
  { id: 'in', label: 'in (comma list)' },
  { id: 'exists', label: 'exists' },
]

/** Ordering operators: the compared field is numeric or temporal by nature. */
const ORDINAL_OPS = new Set<FilterOp>(['gt', 'gte', 'lt', 'lte'])
/** Substring operators: the backend compares string to string only. */
const TEXT_OPS = new Set<FilterOp>(['contains', 'starts_with', 'ends_with'])

/**
 * Coerce a raw string scalar to boolean / number / string.
 *
 * The backend (`seance_core::filter`) treats a number and a string as unequal
 * and has no ordering between them, so a wrongly typed value silently matches
 * nothing. For equality/membership the value may be a forensic identifier, so a
 * number is produced only when it round-trips losslessly (`String(n) === t`):
 * leading zeros ("0123"), pure-digit ids past `Number.MAX_SAFE_INTEGER` and
 * scientific notation ("1e3") stay strings and keep matching the stored string
 * (BUG-199), while genuine numeric input ("42", "-4.5", "0") is still coerced.
 * `numericOnly` (ordering operators) keeps the looser numeric read, where a
 * string value could not be compared at all.
 */
function coerceScalar(raw: string, numericOnly: boolean): unknown {
  const t = raw.trim()
  if (t === 'true') return true
  if (t === 'false') return false
  if (t === '') return raw
  const n = Number(t)
  if (!Number.isFinite(n)) return raw
  return numericOnly || String(n) === t ? n : raw
}

/** Turn form input into a condition value appropriate for the operator. */
export function coerceValue(op: FilterOp, raw: string): unknown {
  if (op === 'exists') return true
  // contains/starts_with/ends_with need both sides to be strings; a coerced
  // number would never match, so the typed text is passed through as-is.
  if (TEXT_OPS.has(op)) return raw
  if (op === 'in') {
    return raw
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s !== '')
      .map((s) => coerceScalar(s, false))
  }
  return coerceScalar(raw, ORDINAL_OPS.has(op))
}

/** Build a Simple condition from form fields. */
export function buildSimpleFilter(
  field: string,
  op: FilterOp,
  raw: string,
): SimpleCondition {
  return { type: 'simple', field, operator: op, value: coerceValue(op, raw) }
}

const OP_LABEL: Record<FilterOp, string> = Object.fromEntries(
  FILTER_OPS.map((o) => [o.id, o.label]),
) as Record<FilterOp, string>

/** Human summary of a (possibly nested) condition, e.g. `extension in [exe, dll]`. */
export function describeCondition(cond: unknown): string {
  if (!cond || typeof cond !== 'object') return 'invalid'
  const c = cond as Record<string, unknown>
  if (c.type === 'simple') {
    const op = OP_LABEL[c.operator as FilterOp] ?? String(c.operator)
    if (c.operator === 'exists') return `${c.field} exists`
    const v = Array.isArray(c.value)
      ? `[${c.value.join(', ')}]`
      : JSON.stringify(c.value)
    return `${c.field} ${op} ${v}`
  }
  if (c.type === 'compound') {
    const parts = (c.conditions as unknown[]).map(describeCondition)
    const joiner = c.logic === 'or' ? ' OR ' : ' AND '
    return `(${parts.join(joiner)})`
  }
  if (c.type === 'not') {
    return `NOT ${describeCondition(c.condition)}`
  }
  return 'invalid'
}

/**
 * One editable row of the compound builder.
 *
 * `negated` belongs to the ROW, not to the group, which is the whole reason the
 * builder can stay unambiguous: a NOT is drawn beside the condition it inverts
 * and cannot be read as applying to anything else.
 */
export interface ConditionRow {
  /** Stable identity for React; never sent to the server. */
  id: string
  field: string
  operator: FilterOp
  value: string
  negated: boolean
}

/** Operators that compare against a value the examiner has to supply. */
const NEEDS_VALUE = new Set<FilterOp>(
  FILTER_OPS.map((o) => o.id).filter((id) => id !== 'exists'),
)

/**
 * Turn the builder's rows into a filter condition, or say why they cannot be
 * turned into one.
 *
 * Refusals rather than repairs, throughout, and each for the same reason: every
 * quiet fix available here changes the POPULATION the filter defines while
 * leaving the screen looking like it describes the one the examiner wrote. A
 * filter's result is what gets counted in a statement and bulk-tagged for a
 * handover, so a filter that matches a different set from the one on screen is
 * a wrong answer about the evidence, not a cosmetic problem.
 *
 * Specifically:
 *
 * - An EMPTY list is refused. `seance_core::filter` evaluates a conjunction of
 *   no conditions as vacuously TRUE — an empty AND matches every artifact in
 *   the case — so a filter saved from an empty builder would carry a name like
 *   "Deleted executables" over the whole case. (An empty OR is the mirror
 *   image: it matches nothing, and reads as an absence finding.) This is pinned
 *   by `seance_api/tests/compound_filter_api_test.rs`.
 *
 * - A row with no FIELD is refused rather than skipped. Skipping it would save
 *   a filter with fewer conditions than the screen shows, i.e. a wider
 *   population than the one the examiner built.
 *
 * - An empty VALUE is refused for every operator that compares one. `contains
 *   ""` is true of every string and `in []` is true of nothing, so an unfilled
 *   row silently widens or empties the population instead of narrowing it.
 *
 * A single row produces the bare condition rather than a one-child compound.
 * The backend treats the two identically, but this JSON is exported and read by
 * people, and a wrapper implies a structure that is not there.
 *
 * Nesting is deliberately not expressible here: every row joins with the same
 * connective, so there is no precedence to get wrong and none to explain. A
 * genuinely nested tree can still arrive by import, and `describeCondition`
 * renders it parenthesised — the builder declines to BUILD what it could not
 * draw unambiguously, which is a different thing from refusing to show it.
 */
export function buildConditionFromRows(
  rows: ConditionRow[],
  logic: 'and' | 'or',
): { condition: FilterCondition } | { error: string } {
  if (rows.length === 0) {
    return {
      error:
        'A filter needs at least one condition. Saved with none, it would match every artifact in the case rather than nothing.',
    }
  }

  const built: FilterCondition[] = []
  for (const [index, row] of rows.entries()) {
    const field = row.field.trim()
    if (field === '') {
      return { error: `Condition ${index + 1} has no field.` }
    }
    if (NEEDS_VALUE.has(row.operator) && row.value.trim() === '') {
      return {
        error: `Condition ${index + 1} has no value. An empty value is not the same as no condition — it would change which artifacts match.`,
      }
    }
    const value = coerceValue(row.operator, row.value)
    if (row.operator === 'in' && Array.isArray(value) && value.length === 0) {
      return {
        error: `Condition ${index + 1} lists no values, so it would match nothing.`,
      }
    }
    const simple: SimpleCondition = {
      type: 'simple',
      field,
      operator: row.operator,
      value,
    }
    built.push(row.negated ? { type: 'not', condition: simple } : simple)
  }

  if (built.length === 1) return { condition: built[0] }
  return { condition: { type: 'compound', logic, conditions: built } }
}
