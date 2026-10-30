// Canonical timestamp coercion for forensic metadata. A single source of truth
// so every viewer agrees on how a raw value maps to wall-clock time — and, now
// that a server-side aggregation must agree with it too, so that both sides
// answer the same question with the same rule instead of two rules that happen
// to look alike. The Rust expression of it is `seance_core::timestamp`, and the
// two are pinned to each other by the shared corpus in
// `src/test/fixtures/epoch-corpus.json`, which both test suites read.

/** 100 ns ticks between the FILETIME epoch (1601) and the Unix epoch (1970). */
const FILETIME_UNIX_OFFSET = 116_444_736_000_000_000
/** JavaScript Date's representable range, ±100,000,000 days in ms. */
const MAX_JS_DATE_MS = 8.64e15

/**
 * How a record's unit was established.
 *
 * `as_written` — read in the unit the record's contract states (whole Unix
 * seconds), or parsed from a written date-time that carries its own offset.
 *
 * `by_rescue` — placed only by assuming which unit the parser used
 * (milliseconds, microseconds, FILETIME ticks). That is a weaker fact than a
 * value read to contract, and a view that shows such an instant has to be able
 * to say so, which is why the confidence travels with it.
 */
export type Confidence = 'as_written' | 'by_rescue'

/**
 * The three-valued answer to "when did this happen?". `unplaceable` keeps two
 * different findings apart: `value` means a listed key was there and no
 * reading of it is admissible; `absent` means no key claimed a time at all.
 *
 * The shape is exactly the `expect` shape of a corpus row, so a test compares a
 * computed placement against the fixture with no translation in between.
 */
export type Placement =
  | { placed_secs: number; confidence: Confidence }
  | { unplaceable: 'value' | 'absent' }

/**
 * The same answer before it is floored to the second it is reported at.
 * Milliseconds are carried this far because the viewers below are handed
 * milliseconds and must agree with the histogram about which second a
 * sub-second value lands in.
 */
type Reading =
  | { ms: number; confidence: Confidence }
  | { unplaceable: 'value' | 'absent' }

/** A present value that no reading of is admissible. */
const unreadable = (): Reading => ({ unplaceable: 'value' })

/**
 * The one decision procedure, applied to a single raw value.
 *
 * `undefined` (an absent key) and `null` are absent — the comms parsers write
 * JSON null to mean "this record carries no time", and that must never surface
 * as 1970-01-01. Anything that is neither a number nor a string is a present
 * value with no reading.
 */
function readValue(v: unknown): Reading {
  if (v === undefined || v === null) return { unplaceable: 'absent' }
  if (typeof v === 'number') return readNumber(v)
  if (typeof v === 'string') return readString(v)
  return unreadable()
}

/**
 * Read a number by magnitude: Windows FILETIME (100 ns ticks since 1601,
 * ~1.3e17), Unix milliseconds (~1e12), Unix seconds (~1e9).
 *
 * Only the seconds band is the documented contract; the other two are rescues,
 * and are marked as such. Values that fall outside JavaScript's Date range are
 * refused rather than allowed to throw downstream in `toISOString()`.
 */
function readNumber(v: number): Reading {
  if (!Number.isFinite(v)) return unreadable()
  let ms: number
  let confidence: Confidence
  if (v > 1e15) {
    ms = (v - FILETIME_UNIX_OFFSET) / 10000 // Windows FILETIME
    confidence = 'by_rescue'
  } else if (v > 1e12) {
    ms = v // Unix milliseconds
    confidence = 'by_rescue'
  } else if (v > 1e8) {
    ms = v * 1000 // Unix seconds
    confidence = 'as_written'
  } else {
    // Below the seconds band. This refuses genuine pre-1973 instants, which is
    // a real loss; it is stated in the corpus rather than left to be found in
    // a case.
    return unreadable()
  }
  return Number.isFinite(ms) && Math.abs(ms) <= MAX_JS_DATE_MS
    ? { ms, confidence }
    : unreadable()
}

/** Read a string: a numeric shape by magnitude, anything else as written text. */
function readString(v: string): Reading {
  if (!v) return unreadable()
  const n = Number(v)
  if (v.trim() !== '' && !Number.isNaN(n) && !/[-:T]/.test(v)) {
    // A FILETIME (~1.3e17) or WebKit microsecond value (~1.3e16) is past
    // Number.MAX_SAFE_INTEGER, so `Number(v)` snaps the tick count to the
    // nearest double before the epoch conversion and can move the result into
    // the neighbouring second. The string still holds the exact ticks, so
    // integer literals are converted with BigInt (B5-005).
    const exact = readIntegerString(v.trim())
    if (exact !== undefined) return exact
    return readNumber(n) // bare numeric string
  }
  const p = Date.parse(v)
  return Number.isNaN(p) ? unreadable() : { ms: p, confidence: 'as_written' }
}

/** Integer literal, the form these tick counts arrive in as strings. */
const INTEGER_LITERAL = /^[+-]?\d+$/

/**
 * Exact `readNumber` for an integer-literal string, in the same magnitude
 * bands. Returns `undefined` (not an unplaceable reading) when the string is
 * not an integer literal, so the caller can tell "not my shape" from "this is
 * not a usable timestamp".
 */
function readIntegerString(s: string): Reading | undefined {
  if (!INTEGER_LITERAL.test(s)) return undefined
  let v: bigint
  try {
    v = BigInt(s)
  } catch {
    return undefined
  }
  let ms: bigint
  let confidence: Confidence
  if (v > 1_000_000_000_000_000n) {
    ms = (v - BigInt(FILETIME_UNIX_OFFSET)) / 10_000n // Windows FILETIME
    confidence = 'by_rescue'
  } else if (v > 1_000_000_000_000n) {
    ms = v // Unix milliseconds
    confidence = 'by_rescue'
  } else if (v > 100_000_000n) {
    ms = v * 1000n // Unix seconds
    confidence = 'as_written'
  } else {
    return unreadable()
  }
  const asNumber = Number(ms)
  return Number.isFinite(asNumber) && Math.abs(asNumber) <= MAX_JS_DATE_MS
    ? { ms: asNumber, confidence }
    : unreadable()
}

/** Whole seconds containing the instant `ms`, rounding towards the past. */
function floorMsToSecs(ms: number): number {
  // Towards the past on both sides of the epoch: an instant half a second
  // before 1970 belongs to the second that starts at -1, not the one at 0.
  // `ms` is floored first so the division sees a whole millisecond count, which
  // is how `seance_core::timestamp` computes the same second.
  return Math.floor(Math.floor(ms) / 1000)
}

/**
 * Coerce one raw metadata value to epoch milliseconds, or null if unusable.
 *
 * Expressed through the same rule as `placeValue` so there is one procedure
 * rather than two that agree by coincidence. Its answers are unchanged: four
 * views read this function, and what it returns is what they render.
 */
export function valueToEpochMs(v: unknown): number | null {
  const r = readValue(v)
  return 'ms' in r ? r.ms : null
}

/**
 * Place one raw metadata value: an instant in whole Unix seconds with the
 * footing it stands on, or the stated reason there is none.
 */
export function placeValue(v: unknown): Placement {
  const r = readValue(v)
  return 'ms' in r
    ? { placed_secs: floorMsToSecs(r.ms), confidence: r.confidence }
    : r
}

/** First of `keys` in `meta` that yields a usable epoch-ms value, else null. */
export function toEpochMs(
  meta: Record<string, unknown>,
  keys: string[],
): number | null {
  for (const k of keys) {
    const r = valueToEpochMs(meta[k])
    if (r != null) return r
  }
  return null
}

/**
 * Place a record by reading `keys` in order.
 *
 * The first key that *yields an instant* wins — not the first key that is
 * non-null. For the live shape `{date: 0, timestamp: 1600000000}` the two
 * readings are fifty years apart, so a server-side COALESCE over the same keys
 * would put a different instant on the same record.
 *
 * Where no key yields an instant, a key that was present but unreadable
 * outranks an absent one in the stated reason: the record did claim a time, and
 * a report must not say it was silent.
 */
export function placeFromMetadata(
  meta: Record<string, unknown>,
  keys: string[],
): Placement {
  let sawPresentValue = false
  for (const k of keys) {
    const p = placeValue(meta[k])
    if ('placed_secs' in p) return p
    if (p.unplaceable === 'value') sawPresentValue = true
  }
  return { unplaceable: sawPresentValue ? 'value' : 'absent' }
}

/**
 * The four answers the ordered census counts, spelled exactly as the server
 * spells them (`seance_core::timestamp::Placement::census_class`) so the two
 * cannot drift apart in a report's wording.
 */
export type CensusClass =
  | 'placed_as_written'
  | 'placed_by_rescue'
  | 'unplaceable_value'
  | 'unplaceable_absent'

/** The census class of a placement. */
export function censusClass(p: Placement): CensusClass {
  return 'placed_secs' in p
    ? p.confidence === 'by_rescue'
      ? 'placed_by_rescue'
      : 'placed_as_written'
    : p.unplaceable === 'value'
      ? 'unplaceable_value'
      : 'unplaceable_absent'
}
