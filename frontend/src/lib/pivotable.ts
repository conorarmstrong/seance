/**
 * Which metadata values are worth pivoting on, decided from the key name.
 *
 * The tailored record viewers mark their identifier columns by hand, because
 * the author of a viewer knows which of its columns an examiner follows. The
 * artifact inspector cannot: it renders whatever keys the parser wrote, so it
 * needs a rule.
 *
 * The rule is an **allow-list**, deliberately. A pivot on every value would
 * put a trigger on `size: 4096`, `is_directory: false` and
 * `content_incomplete_reason: cap_reached` — and "every artifact in this case
 * that references 4096" is noise that teaches an examiner to distrust the
 * affordance. So a key nobody has classified is *not* pivotable, and a new
 * parser key defaults to plain text until someone decides it is an identifier.
 *
 * What counts as an identifier is the thing a case is followed by: an address,
 * a hash, an account, a device serial, a file name. Counts, sizes, offsets,
 * flags, versions, durations, reasons and prose are not, whatever they are
 * called.
 */

/**
 * Key-name patterns whose values are identifiers. Matched against the
 * lower-cased key, on whole `_`-separated segments where a bare substring
 * would over-match (`name` must not match `rcode_name` or `flag_names`).
 */
const IDENTIFIER_PATTERNS: readonly RegExp[] = [
  // Hashes. `_hash` covers sha1_hash/entry_hash/pdq_hash; the bare algorithm
  // names cover md5/sha1/sha256 written without a suffix.
  /(^|_)(md5|sha1|sha224|sha256|sha384|sha512|imphash|pdq|ahash|dhash|phash)(_|$)/,
  /_hash$/,
  // Network identifiers.
  /(^|_)(ip|ipv4|ipv6|addr|address|host|hostname|peer|domain|fqdn|url|uri|mac)(_|$)/,
  // Accounts and principals.
  /(^|_)(user|username|account|sid|owner|email|mailbox|principal|upn)(_|$)/,
  // Device and installation identifiers.
  /(^|_)(serial|imei|imsi|iccid|udid|meid|device_id|machine_id|guid|uuid)(_|$)/,
  // File and program names, and the paths that hold them.
  /(^|_)(filename|file_name|executable|executable_name|original_filename|bundle_id|package|package_name)(_|$)/,
  /(^|_)(path|file_path|full_path|original_path|source_path|stored_path)(_|$)/,
  // A bare `name`, but only as the whole key or a `*_name` this list already
  // names — never as a fragment of `rcode_name`, `flag_names`, `role_name`.
  /^name$/,
  /(^|_)(display_name|device_name|computer_name|product_name|folder_name)(_|$)/,
]

/**
 * Keys that match a pattern above but whose values are not identifiers. Kept
 * as an explicit list so the exception is visible rather than hidden in a
 * cleverer regex.
 */
const NOT_IDENTIFIERS: readonly RegExp[] = [
  // A time is not an identifier, however it is named.
  /(^|_)(time|timestamp|date|_at)(_|$)/,
  /_(time|timestamp|date)$/,
  // Our own honesty vocabulary: reasons, details, notes and messages are
  // prose the product wrote, not evidence to follow.
  /(^|_)(reason|detail|details|note|notes|message|summary|description)(_|$)/,
  // Counts and sizes that happen to carry an identifier word.
  /(^|_)(count|total|size|length|bytes|offset)(_|$)/,
]

/** Longest value worth offering a pivot on. */
const MAX_PIVOT_VALUE_LEN = 256

/**
 * Is `key` the name of an identifier — something an examiner follows across
 * the case?
 */
export function isPivotableKey(key: string): boolean {
  const k = key.toLowerCase()
  if (NOT_IDENTIFIERS.some((re) => re.test(k))) return false
  return IDENTIFIER_PATTERNS.some((re) => re.test(k))
}

/**
 * Is `value` worth pivoting on at all, whatever its key?
 *
 * A pivot needs a string an index can be asked about. A boolean, a number, a
 * blob, a multi-line block or an empty string is not one — and a pivot that
 * returns the whole case, or nothing, is worse than no pivot.
 */
export function isPivotableValue(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const v = value.trim()
  if (v === '') return false
  if (v.length > MAX_PIVOT_VALUE_LEN) return false
  if (/[\n\r]/.test(v)) return false
  // A bare boolean or a plain integer is a property, not an identifier —
  // even under a key like `owner`. (A dotted quad is not a plain integer.)
  if (/^(true|false)$/i.test(v)) return false
  if (/^-?\d+$/.test(v)) return false
  return true
}

/**
 * The pivot target for a metadata entry, or `null` when there is none. The one
 * call the inspector makes per row.
 */
export function pivotTarget(key: string, value: unknown): string | null {
  if (!isPivotableKey(key)) return null
  if (!isPivotableValue(value)) return null
  return value.trim()
}
