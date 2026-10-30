/**
 * In-place timestamp interpretation for the SQLite viewer.
 *
 * App databases store times in many encodings; an examiner needs to reinterpret
 * a raw column value (usually an integer) as a date without leaving the grid.
 * These are the encodings that actually turn up in forensic SQLite stores.
 */

export type TimeFormat =
  | 'raw'
  | 'unix_s'
  | 'unix_ms'
  | 'webkit'
  | 'cocoa'
  | 'filetime'
  | 'iso'

/** Selectable interpretations, in menu order. */
export const TIME_FORMATS: { id: TimeFormat; label: string }[] = [
  { id: 'raw', label: 'Raw value' },
  { id: 'unix_s', label: 'Unix (seconds)' },
  { id: 'unix_ms', label: 'Unix (milliseconds)' },
  { id: 'webkit', label: 'WebKit / Chrome (µs since 1601)' },
  { id: 'cocoa', label: 'Cocoa / Mac (s since 2001)' },
  { id: 'filetime', label: 'Windows FILETIME (100 ns since 1601)' },
  { id: 'iso', label: 'ISO 8601 string' },
]

/** Milliseconds between 1601-01-01 and 1970-01-01 (WebKit / FILETIME epoch). */
const WEBKIT_EPOCH_MS = 11_644_473_600_000
/** Seconds between 1970-01-01 and 2001-01-01 (Cocoa / Core Data epoch). */
const COCOA_EPOCH_S = 978_307_200

/** Integer literal, the form every one of these encodings is stored in. */
const INTEGER_LITERAL = /^[+-]?\d+$/

/**
 * Exact epoch-ms for an integer-literal raw value, using BigInt.
 *
 * A present-day FILETIME is around 1.3e17 and a WebKit microsecond value around
 * 1.3e16; both are past `Number.MAX_SAFE_INTEGER` (9.007e15), so `Number(raw)`
 * snaps the tick count to the nearest representable double BEFORE the epoch
 * conversion. Near a second boundary that rounding moves the decoded time into
 * the next second, and the grid then shows an examiner a wall-clock second that
 * the database does not contain. The raw column value is a string here, so the
 * arithmetic can be done exactly and is (B5-005).
 *
 * Returns null when `raw` is not an integer literal; the caller falls back to
 * the double path, which is exact for the small/fractional values it handles.
 */
function exactEpochMs(raw: string, fmt: TimeFormat): number | null {
  if (!INTEGER_LITERAL.test(raw)) return null
  let n: bigint
  try {
    n = BigInt(raw)
  } catch {
    return null
  }
  let ms: bigint
  switch (fmt) {
    case 'unix_s':
      ms = n * 1000n
      break
    case 'unix_ms':
      ms = n
      break
    case 'webkit':
      ms = n / 1000n - BigInt(WEBKIT_EPOCH_MS)
      break
    case 'filetime':
      ms = n / 10_000n - BigInt(WEBKIT_EPOCH_MS)
      break
    case 'cocoa':
      ms = (n + BigInt(COCOA_EPOCH_S)) * 1000n
      break
    default:
      return null
  }
  // Every millisecond inside JavaScript's Date range is exactly representable
  // as a double (the range is under 2^53), so this conversion is lossless for
  // anything that can be shown at all. Outside it, the caller's year check
  // rejects the value.
  const asNumber = Number(ms)
  return Number.isFinite(asNumber) ? asNumber : null
}

/**
 * Decode `raw` under a timestamp interpretation, returning an ISO-8601 UTC
 * string, or `null` when the value can't sensibly be a date under that format
 * (non-numeric, or a year outside 1601–2200). `null` lets the caller fall back
 * to the raw value, so a wrong interpretation reads as "no date" rather than a
 * plausible-but-false one. `'raw'` always returns `null` (show the raw value).
 */
export function decodeTimestamp(raw: string, fmt: TimeFormat): string | null {
  if (fmt === 'raw') return null

  if (fmt === 'iso') {
    const t = Date.parse(raw)
    return Number.isNaN(t) ? null : isoUtc(t)
  }

  // `Number('')` and `Number('  ')` are 0, not NaN, so guard blanks explicitly.
  const trimmed = raw.trim()
  if (trimmed === '') return null
  const n = Number(trimmed)
  if (!Number.isFinite(n)) return null

  // Integer tick counts are decoded exactly; only fractional/odd values fall
  // through to double arithmetic.
  const exact = exactEpochMs(trimmed, fmt)
  if (exact != null) return finishDecode(exact)

  let ms: number
  switch (fmt) {
    case 'unix_s':
      ms = n * 1000
      break
    case 'unix_ms':
      ms = n
      break
    case 'webkit':
      ms = n / 1000 - WEBKIT_EPOCH_MS
      break
    case 'filetime':
      ms = n / 10_000 - WEBKIT_EPOCH_MS
      break
    case 'cocoa':
      ms = (n + COCOA_EPOCH_S) * 1000
      break
    default:
      return null
  }

  return finishDecode(ms)
}

/** Range-check a decoded epoch-ms and format it, or reject it. */
function finishDecode(ms: number): string | null {
  if (!Number.isFinite(ms)) return null
  const d = new Date(ms)
  const year = d.getUTCFullYear()
  // Reject gross mis-interpretations so the examiner can try another format.
  if (Number.isNaN(year) || year < 1601 || year > 2200) return null
  return isoUtc(ms)
}

/** Format epoch-ms as `YYYY-MM-DDTHH:MM:SSZ` (drop sub-second noise). */
function isoUtc(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')
}
