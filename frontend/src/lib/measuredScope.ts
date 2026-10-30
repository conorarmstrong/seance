/**
 * How much of a thing the figure beside it actually covers.
 *
 * This is the sibling problem to `lib/incompleteness.ts`, and deliberately not
 * the same thing. The incompleteness pair says "the bytes behind this record
 * were not all there" — something went wrong. What this module reads is the
 * other case: the bytes were all there, the parser read them fine, and it
 * *chose* to measure only part of them. A prefix sample, a capped string, a
 * path cut at a buffer edge.
 *
 * That distinction matters enough that the plugin tree keeps it: stamping the
 * incompleteness pair on every file larger than an entropy window would put
 * most of a disk image into the court-facing incompleteness count and bury the
 * artifacts whose bytes really were missing. So those producers declare the
 * sample on their own keys instead — and a bespoke key is read by nobody unless
 * something like this reads it.
 *
 * The failure this exists to stop: `seance_plugin_file_analysis` measures
 * Shannon entropy over at most the first 192 KiB of a file and sets
 * `entropy_sampled` / `entropy_bytes` / `entropy_note` to say so. Nothing read
 * those keys, so the Analysis viewer printed the figure as *the file's
 * entropy*. Entropy is what an examiner uses to judge whether content is
 * encrypted or packed; an installer with a plaintext manifest ahead of a packed
 * payload measures low over its prefix. "Low entropy: not encrypted" read off a
 * prefix is a quantitative claim about bytes nobody measured.
 *
 * Nothing here guesses. A producer that always writes its flag and did not
 * write it on this record has told us nothing, and "we were not told" renders
 * as its own word — never as "whole". That is the same rule the memory pages
 * follow for `not_declared` / `unavailable` / `not_applicable`.
 */

/** What a figure's own metadata says about the extent it covers. */
export type ScopeState =
  /** The producer says the figure covers the whole thing. */
  | 'whole'
  /** The producer says the figure covers only part of the thing. */
  | 'partial'
  /**
   * The producer said nothing readable about the extent. Not "whole": an
   * unqualified number and a number qualified as complete are different claims,
   * and only one of them was made.
   */
  | 'undeclared'

/** One figure's declared extent, read off an artifact's metadata. */
export interface MeasuredScope {
  state: ScopeState
  /** How much was actually covered, when the producer said. */
  measured: number | null
  /** How much there was in total, when the producer said. */
  total: number | null
  /**
   * The producer's own sentence about this record (`*_note`), when it wrote
   * one. Shown verbatim: it is the only part of the declaration that can say
   * something about this record rather than about its category.
   */
  note: string | null
}

/**
 * Where one producer's extent declaration lives, and how to say it.
 *
 * Held as named constants below rather than spelled at each call site, so the
 * contract each plugin actually writes is recorded in one greppable place. The
 * contracts genuinely differ: some producers stamp their flag on every record
 * (`false` when whole), others only when the answer is "partial". Getting that
 * backwards either cries wolf on every row or hides the one row that matters.
 */
export interface ScopeSpec {
  /** Boolean metadata key, true when the figure covers only part. */
  flag: string
  /**
   * True when the producer writes `flag` on every record it emits. Only then
   * does an absent flag mean "we were not told"; for a producer that stamps the
   * flag only when it is true, an absent flag is the producer saying "whole".
   */
  alwaysDeclared: boolean
  /**
   * Key holding how much was covered (same unit as `totalKey`).
   *
   * Declare this pair only where `measured < total` means exactly "this figure
   * covers less than the whole thing" — `readScope` treats a shortfall in the
   * counts as proof of a partial figure even when the flag says otherwise.
   */
  measuredKey?: string
  /** Key holding how much there was in total. */
  totalKey?: string
  /** Key holding the producer's own sentence. */
  noteKey?: string
  /** Unit of `measuredKey` / `totalKey`, for phrasing the fallback sentence. */
  unit: 'bytes' | 'count'
  /** One word for the badge, e.g. `sampled`, `truncated`. */
  word: string
  /** How the sentences name the figure, e.g. "This entropy figure". */
  subject: string
  /**
   * What `partial` means for this figure, used when the producer wrote no
   * sentence of its own. Must say what the figure does *not* support.
   */
  partialMeaning: string
}

/** Coerce a metadata value to a finite number, or null. */
function num(meta: Record<string, unknown>, key: string | undefined): number | null {
  if (key == null) return null
  const v = meta[key]
  if (typeof v === 'number' && Number.isFinite(v)) return v
  if (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))) {
    return Number(v)
  }
  return null
}

/** Coerce a metadata value to a non-empty trimmed string, or null. */
function str(meta: Record<string, unknown>, key: string | undefined): string | null {
  if (key == null) return null
  const v = meta[key]
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : null
}

/**
 * Read one figure's declared extent off a metadata blob.
 *
 * A flag that is present but is neither a boolean nor `"true"`/`"false"` is
 * reported `undeclared`, never `whole`: JSON that cannot be read is not
 * evidence that the measurement was complete.
 *
 * The producer's own counts outrank its flag. A flag answers a question the
 * producer chose to ask itself, and it may not be the question an examiner is
 * asking: `entropy_sampled` is set from the WINDOW the plugin was entitled to
 * read (192 KiB against the file size), not from what came back. A 2 KiB file
 * whose read returned 100 bytes is therefore stamped `entropy_sampled: false`
 * with `entropy_bytes: 100` and `entropy_file_bytes: 2048` — a figure over 5%
 * of a file, flagged as covering all of it. Where the counts say the
 * measurement fell short they decide, because they are the checkable half and
 * because a disagreement must never resolve toward the completeness claim.
 */
export function readScope(
  metadata: Record<string, unknown> | null | undefined,
  spec: ScopeSpec,
): MeasuredScope {
  if (metadata == null) {
    return { state: 'undeclared', measured: null, total: null, note: null }
  }
  const measured = num(metadata, spec.measuredKey)
  const total = num(metadata, spec.totalKey)
  const note = str(metadata, spec.noteKey)
  const raw = metadata[spec.flag]
  let state: ScopeState
  if (raw === true || raw === 'true') state = 'partial'
  else if (raw === false || raw === 'false') state = 'whole'
  else if (raw === undefined || raw === null) {
    state = spec.alwaysDeclared ? 'undeclared' : 'whole'
  } else state = 'undeclared'
  if (measured != null && total != null && measured < total) state = 'partial'
  return { state, measured, total, note }
}

// Fixed locale, as elsewhere in the app: an extent quoted in a report must read
// the same on every examiner's machine.
const numberFmt = new Intl.NumberFormat('en-US')

/** Exact grouped count, for an extent shown beside the figure it qualifies. */
export function formatExtent(value: number): string {
  return numberFmt.format(value)
}

function amount(value: number, unit: ScopeSpec['unit']): string {
  if (unit === 'bytes') {
    // Exact bytes, not a rounded human size: this number is the extent of a
    // measurement offered as evidence, and "192.0 KiB" cannot be checked
    // against a file the way 196608 can.
    return `${formatExtent(value)} byte${value === 1 ? '' : 's'}`
  }
  return formatExtent(value)
}

/**
 * The sentence an examiner reads about this figure's extent.
 *
 * Empty for a `whole` figure — a qualifier that is always present is one an
 * examiner learns to skip. For `partial`, the producer's own sentence wins
 * where it wrote one, because it is the only text that can describe this
 * record; the numbers are appended when it did not.
 */
export function scopeSentence(scope: MeasuredScope, spec: ScopeSpec): string {
  if (scope.state === 'whole') return ''
  if (scope.state === 'undeclared') {
    return (
      `${spec.subject} does not declare how much of the underlying data it covers, ` +
      `so it cannot be read as covering all of it.`
    )
  }
  if (scope.note) return scope.note
  const extent =
    scope.measured != null && scope.total != null
      ? ` It covers ${amount(scope.measured, spec.unit)} of ${amount(scope.total, spec.unit)}.`
      : scope.measured != null
        ? ` It covers ${amount(scope.measured, spec.unit)}.`
        : scope.total != null
          ? // Half the pair: the producer stated the whole and not the part.
            // Still worth saying — it is the scale of what is missing.
            ` The whole is ${amount(scope.total, spec.unit)}.`
          : ''
  return `${spec.subject} covers only part of the underlying data.${extent} ${spec.partialMeaning}`
}

/** The word shown on the badge, or empty for a figure declared whole. */
export function scopeWord(scope: MeasuredScope, spec: ScopeSpec): string {
  if (scope.state === 'whole') return ''
  return scope.state === 'partial' ? spec.word : 'scope not stated'
}

/**
 * Suffix for a bucket label in a frequency chart.
 *
 * A classification derived from a prefix and one derived from the whole thing
 * must not land in the same bar: the bar is read as "N files are high-entropy",
 * and the sampled ones do not support that. Empty for a figure declared whole,
 * so a chart over sound data is unchanged.
 */
export function scopeLabelSuffix(scope: MeasuredScope, spec: ScopeSpec): string {
  if (scope.state === 'whole') return ''
  return scope.state === 'partial' ? ` (${spec.word})` : ' (scope not stated)'
}

// ---------------------------------------------------------------------------
// The declarations the plugin tree actually writes.
// ---------------------------------------------------------------------------

/**
 * `seance_plugin_file_analysis`: Shannon entropy over at most the first 192 KiB.
 * The flag is written on every record (`false` when the file fitted inside the
 * window), so an absent flag means the record predates the declaration.
 *
 * The flag alone is not enough. It compares the window with the file, not the
 * bytes that came back with the file: a small file whose read fell short is
 * flagged `false` while `entropy_bytes` is a fraction of `entropy_file_bytes`.
 * The counts are declared here so `readScope` catches that case.
 */
export const ENTROPY_SCOPE: ScopeSpec = {
  flag: 'entropy_sampled',
  alwaysDeclared: true,
  measuredKey: 'entropy_bytes',
  totalKey: 'entropy_file_bytes',
  noteKey: 'entropy_note',
  unit: 'bytes',
  word: 'sampled',
  subject: 'This entropy figure',
  partialMeaning:
    'It describes that prefix, not the file, so it does not establish whether the rest of the file is encrypted, packed or plain.',
}

/**
 * `seance_plugin_win_timeline`: the captured clipboard text, cut at a storage
 * cap. The flag is written whenever clipboard text is present.
 */
export const CLIPBOARD_TEXT_SCOPE: ScopeSpec = {
  flag: 'clipboard_text_truncated',
  alwaysDeclared: true,
  totalKey: 'clipboard_bytes',
  unit: 'bytes',
  word: 'truncated',
  subject: 'This clipboard capture',
  partialMeaning:
    'What was copied continued past the end of the text shown, so the absence of a word here is not evidence it was not copied.',
}

/**
 * `seance_plugin_win_timeline`: the raw AppId blob, cut at a storage cap. The
 * flag is written whenever a raw AppId is present.
 */
export const APP_ID_RAW_SCOPE: ScopeSpec = {
  flag: 'app_id_raw_truncated',
  alwaysDeclared: true,
  unit: 'count',
  word: 'truncated',
  subject: 'This raw AppId',
  partialMeaning:
    'Identities recorded past the cut are not shown, so this is not the full set of applications the activity names.',
}

/**
 * `seance_plugin_email`: the message body, cut at 64 KiB by `truncate_str`.
 * All three producers (`eml`, `msg`, `pst`) write the flag on every
 * `EmailMessage` they emit, so an absent flag means the record predates the
 * declaration.
 *
 * The parser appends a `...[truncated]` sentinel inside the text, and its own
 * source comment says why that is not the answer: the sentinel is prose, and
 * search, export and this UI all treat the field as the message body. A body
 * is quoted in reports more often than any other field here, and a message
 * that continued past the cut reads on screen as the whole of what was
 * written.
 */
export const EMAIL_BODY_SCOPE: ScopeSpec = {
  flag: 'body_truncated',
  alwaysDeclared: true,
  unit: 'count',
  word: 'truncated',
  subject: 'This message body',
  partialMeaning:
    'The message continued past the end of the text shown, so the absence of a word here is not evidence it was never written.',
}

/**
 * `seance_plugin_recyclebin`: the deleted file's original path, cut short when
 * the `$I` record ran out before the path terminator. Stamped only when true,
 * so an absent flag is the parser saying the path is whole.
 *
 * The cut is at the END of the path, which is where the file name and its
 * extension are — so anything derived from the tail of a truncated path is
 * derived from a fragment.
 */
export const RECYCLE_ORIGINAL_PATH_SCOPE: ScopeSpec = {
  flag: 'original_path_truncated',
  alwaysDeclared: false,
  unit: 'count',
  word: 'truncated',
  subject: "This deleted file's original path",
  partialMeaning:
    'The record ran out before the path ended, so the file name and extension shown are a fragment of the real path.',
}
