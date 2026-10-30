const MISSING = '—'

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']

export function formatBytes(size: number | null | undefined): string {
  if (size == null || Number.isNaN(size)) return MISSING
  if (size < 1024) return `${size} B`
  let value = size
  let unit = 0
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(1)} ${UNITS[unit]}`
}

/**
 * Every figure in this application is grouped and pointed the same way on every
 * machine, because these numbers are quoted into statements and exhibits. Left
 * to the runtime locale, an examiner on de-DE reads "93.338" where a colleague
 * on en-GB reads "93,338" for the same evidence, and on each of their machines
 * the other's string denotes a different number. Two examiners looking at one
 * case must not be shown different facts, so the locale is pinned rather than
 * followed. en-US is the pin only because the codebase already used it.
 */
const COUNT_FORMAT = new Intl.NumberFormat('en-US')

/** Whole counts — artifacts, records, rows — with pinned thousands separators. */
export function formatCount(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return MISSING
  return COUNT_FORMAT.format(n)
}

const DECIMAL_FORMATS = new Map<number, Intl.NumberFormat>()

/**
 * Fractional figures — rates, percentages — with a pinned decimal point and a
 * fixed number of fraction digits, so a rate never arrives in a report with its
 * point and its thousands separator swapped. See COUNT_FORMAT for why.
 */
export function formatDecimal(
  n: number | null | undefined,
  digits = 1,
): string {
  if (n == null || Number.isNaN(n)) return MISSING
  // Constructing an Intl.NumberFormat is expensive relative to formatting with
  // one, and these helpers are called from render paths that redraw on every
  // progress event, so keep one formatter per digit count.
  let fmt = DECIMAL_FORMATS.get(digits)
  if (!fmt) {
    fmt = new Intl.NumberFormat('en-US', {
      minimumFractionDigits: digits,
      maximumFractionDigits: digits,
    })
    DECIMAL_FORMATS.set(digits, fmt)
  }
  return fmt.format(n)
}

/**
 * Forensic timestamps are always displayed in UTC with an explicit label,
 * never in the examiner's local timezone.
 */
export function formatUtc(iso: string | null | undefined): string {
  if (!iso) return MISSING
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return MISSING
  const pad = (n: number) => String(n).padStart(2, '0')
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC`
  )
}

export function truncateHash(hash: string | null | undefined): string {
  if (!hash) return MISSING
  if (hash.length <= 20) return hash
  return `${hash.slice(0, 8)}…${hash.slice(-8)}`
}
