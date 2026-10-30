/**
 * The standard incompleteness pair, read the way the plugin tree writes it.
 *
 * Parsers across the whole plugin tree stamp two keys onto an artifact whenever
 * what they produced is not all there was:
 *
 * - `content_incomplete` / `content_incomplete_reason` — the bytes behind this
 *   record are not the whole thing (a cap was hit, a read came up short, a
 *   structure could not be resolved, the data was left encrypted or
 *   compressed);
 * - `inventory_incomplete` / `inventory_incomplete_reason` — the LISTING is
 *   short: rows, keys or entries exist that are not in this result;
 * - `directory_parse_incomplete` / `directory_parse_incomplete_reason` — the
 *   filesystem parsers' (ext4, FAT/exFAT, XFS, btrfs, APFS, ISO 9660) name for
 *   the same thing about one FOLDER: files exist in it that are not in the
 *   listing. It predates the pair and is stamped on the directory's own
 *   artifact, so it is read here rather than left to a fourth phrasing.
 *
 * Each flag may also carry a `<flag>_detail` string: the sentence the parser
 * wrote about what happened, and a `<flag>_reasons` list naming every reason
 * when there was more than one (the jump-list parser, and the SQLite staging
 * stamp, which keeps the first reason primary and lists a short read beside
 * it). Every listed reason is shown (UI-042). Where a detail exists it is shown, because it says what
 * the machine token cannot ("7z uses solid compression; per-entry content is
 * not extracted by this ingest" is actionable, "compressed" is a category).
 *
 * The stamps only mean something if the examiner meets them. This module is the
 * one place the pair is read, so every surface that shows artifact-derived
 * records reports it identically instead of each page inventing a phrase.
 *
 * The reason is carried through deliberately: "a safety cap stopped the read"
 * and "rows could not be decoded" call for different follow-up, and an examiner
 * given only "incomplete" cannot tell which they are looking at.
 *
 * Nothing here guesses. A flag stamped without a reason says the reason was not
 * recorded; a flag that is present but not a boolean says it could not be read.
 * Neither is ever reported as complete.
 */

/** Which part of an artifact an incompleteness stamp is about. */
export type IncompleteScope = 'content' | 'inventory' | 'directory'

/** One incompleteness stamp read off an artifact's metadata. */
export interface Incompleteness {
  scope: IncompleteScope
  /**
   * The stable machine reason the plugin stamped, or `null` when it set the
   * flag and recorded no reason. `null` is not "no problem" — it is "we were
   * not told why", which is itself worth showing.
   */
  reason: string | null
  /**
   * The parser's own sentence about this stamp (`<flag>_detail`), or `null`
   * when it wrote none. Shown verbatim: it is the only part of the stamp that
   * can say something the fixed vocabulary has no token for.
   */
  detail: string | null
  /**
   * Every further reason the record listed under `<flag>_reasons`, beyond
   * `reason`, in the order the parser recorded them. Absent when there is
   * none. A record can be short for two reasons at once — a structure that
   * would not resolve, and a database that was not staged in full — and the
   * second is a different follow-up, so it is never dropped (UI-042).
   */
  additionalReasons?: string[]
}

/**
 * Reason stamped by this module (not by a plugin) when the flag is present but
 * is not a boolean, so JSON that cannot be trusted is not read as "complete".
 */
export const UNREADABLE_FLAG_REASON = 'incompleteness_flag_unreadable'

const SCOPE_KEYS: Record<
  IncompleteScope,
  { flag: string; reason: string; reasons: string; detail: string }
> = {
  content: {
    flag: 'content_incomplete',
    reason: 'content_incomplete_reason',
    reasons: 'content_incomplete_reasons',
    detail: 'content_incomplete_detail',
  },
  inventory: {
    flag: 'inventory_incomplete',
    reason: 'inventory_incomplete_reason',
    reasons: 'inventory_incomplete_reasons',
    detail: 'inventory_incomplete_detail',
  },
  directory: {
    flag: 'directory_parse_incomplete',
    reason: 'directory_parse_incomplete_reason',
    reasons: 'directory_parse_incomplete_reasons',
    detail: 'directory_parse_incomplete_detail',
  },
}

const SCOPES: IncompleteScope[] = ['content', 'inventory', 'directory']

/** Anything carrying an untyped metadata blob: an artifact, a parsed record. */
export interface HasMetadata {
  metadata?: Record<string, unknown> | null
}

function reasonOf(
  metadata: Record<string, unknown>,
  key: string,
): string | null {
  const value = metadata[key]
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : null
}

/** The non-empty strings of a `<flag>_reasons` list, deduplicated, in order. */
function reasonList(metadata: Record<string, unknown>, key: string): string[] {
  const value = metadata[key]
  if (!Array.isArray(value)) return []
  const out: string[] = []
  for (const item of value) {
    if (typeof item !== 'string') continue
    const reason = item.trim()
    if (reason !== '' && !out.includes(reason)) out.push(reason)
  }
  return out
}

/**
 * Every incompleteness stamped on one metadata blob, in scope order.
 *
 * An empty array means the metadata claims the result is whole. A record whose
 * flag is absent altogether is treated as complete, because that is what an
 * unstamped artifact from a parser with nothing to report looks like — the
 * plugin tree stamps `false` or nothing at all when it finished the job.
 */
export function readIncompleteness(
  metadata: Record<string, unknown> | null | undefined,
): Incompleteness[] {
  if (metadata == null) return []
  const out: Incompleteness[] = []
  for (const scope of SCOPES) {
    const keys = SCOPE_KEYS[scope]
    const flag = metadata[keys.flag]
    if (flag === undefined || flag === null || flag === false) continue
    const detail = reasonOf(metadata, keys.detail)
    if (flag === true) {
      // The singular reason is primary; the list adds what it does not name.
      // A record that wrote only the list takes its first entry as primary.
      const listed = reasonList(metadata, keys.reasons)
      const reason = reasonOf(metadata, keys.reason) ?? listed[0] ?? null
      const additional = listed.filter((r) => r !== reason)
      const stamp: Incompleteness = { scope, reason, detail }
      if (additional.length > 0) stamp.additionalReasons = additional
      out.push(stamp)
      continue
    }
    // Present but not a boolean: the truth cannot be determined from it, and
    // "cannot determine" must never be rendered as "complete".
    out.push({ scope, reason: UNREADABLE_FLAG_REASON, detail })
  }
  return out
}

/**
 * Human phrase for a stamped reason, falling back to the raw token.
 *
 * The vocabulary is open: `seance_core`'s `IncompleteReason` supplies the five
 * shared reasons, and individual parsers stamp their own more specific ones
 * (`hive_not_read_in_full`, `btrfs_missing_device`, `bagmru_depth_limit`, …).
 * An unknown reason is shown, de-underscored, rather than swallowed — losing it
 * would leave the examiner with a warning and no way to act on it.
 */
export function incompleteReasonLabel(reason: string | null): string {
  if (reason == null) return 'no reason was recorded'
  const known = REASON_PHRASE[reason]
  if (known) return known
  return reason.replace(/_/g, ' ')
}

const REASON_PHRASE: Record<string, string> = {
  // seance_core::io::IncompleteReason — the shared set.
  cap_reached: 'a parser safety cap stopped the read before the end of the data',
  short_read: 'a read returned fewer bytes than the structure requires',
  unresolved_structure:
    'a structure referenced data that could not be located or parsed',
  encrypted: 'the content is encrypted at rest and was not decrypted',
  compressed: 'the content is compressed and was not decompressed',
  // Loud on purpose: not a gap but a warning about everything that decoded.
  // The bytes came from a codepath no ground-truth corpus has ever checked, so
  // they may be structurally plausible and still wrong — treat as unverified.
  unvalidated:
    'these bytes were produced by a codepath never validated against ground truth, so they may be structurally plausible but wrong — treat everything it produced as unverified',
  // Deliberately not phrased as a gap. Nothing was there to read, so unlike
  // every other reason here it does not mean evidence may have been missed —
  // and a reader skimming a list of incompleteness notes must be able to tell
  // that one apart from the rest at a glance.
  unmapped:
    'this range was never mapped, so there were no bytes to read and nothing could have been stored there',
  // Stamped by the orchestrator on a root exhibit whose processing a stopped
  // or cancelled process never finished (HUNT-113). The count under such a
  // source is what was recorded before it stopped, not what it holds.
  ingest_interrupted:
    'processing of this source stopped before its walk ended, so what the walk had not reached is absent from the case, not from the evidence',
  // The closed set the filesystem parsers stamp on a short folder listing.
  // Left to the de-underscoring fallback these read as parser jargon in a
  // report; each one names a different thing an examiner would do next.
  fat_chain_incomplete:
    "the FAT cluster chain for this folder could not be followed to its end, so the folder's later entries were never read",
  fat_root_chain_incomplete:
    'the FAT root directory chain could not be followed to its end, so entries in the root were never read',
  exfat_chain_incomplete:
    "the exFAT cluster chain for this folder could not be followed to its end, so the folder's later entries were never read",
  exfat_root_chain_incomplete:
    'the exFAT root directory chain could not be followed to its end, so entries in the root were never read',
  btrfs_max_dir_entries:
    'this folder holds more entries than the btrfs directory cap reads, so the listing stops at the cap',
  apfs_max_dir_entries:
    'this folder holds more entries than the APFS directory cap reads, so the listing stops at the cap',
  xfs_max_dir_entries:
    'this folder holds more entries than the XFS directory cap reads, so the listing stops at the cap',
  // `seance_plugin_file_analysis`'s hidden-data (overlay) check, for the two
  // ways it can decline to run. Read through the same label function so the
  // product has one reason vocabulary rather than one per check.
  no_logical_end_walker_for_format:
    'this build has no walker for this file format, so it has no logical end to measure a tail against',
  content_type_not_identified:
    "the content type could not be identified from the file's leading bytes, so there is no format terminator to walk to",
  // Stamped here, never by a plugin.
  [UNREADABLE_FLAG_REASON]:
    'the completeness flag on this record was not a true/false value, so whether it is whole could not be established',
}

/** What one scope of incompleteness means for what is on screen. */
export const SCOPE_MEANING: Record<IncompleteScope, string> = {
  content:
    'The bytes behind this are not all of it. Anything derived from them — a hash, a preview, an export, a count — covers only the part that was read.',
  inventory:
    'This listing is short. Entries exist in the evidence that are not shown here, so an absence below is not evidence of absence.',
  directory:
    "This folder's listing is short. Files exist in this folder in the evidence that the filesystem parser did not enumerate, so a file missing from it was not necessarily missing from the device.",
}

/** Short word for a scope, for a badge with no room for a sentence. */
export const SCOPE_LABEL: Record<IncompleteScope, string> = {
  content: 'content incomplete',
  inventory: 'listing incomplete',
  directory: 'folder listing incomplete',
}

/**
 * Was this record's statement answered by a later run?
 *
 * A re-run can settle what an earlier one refused: a password opens a backup
 * recorded as unreadable, a symbol pack arrives after a memory pass gave up.
 * The earlier record is kept — that the refusal happened is part of the case —
 * and marked `superseded`, with `superseded_by` naming the record that answered
 * it. The backend census excludes it from the figures a report draws its "not
 * recovered" section from, so every screen must agree: showing a plain
 * "incomplete" warning on a record the case has since answered would tell an
 * examiner data is missing that is sitting in the same case (HUNT-090).
 */
export function isSuperseded(
  metadata: Record<string, unknown> | null | undefined,
): boolean {
  return metadata?.superseded === true
}

/** The id of the record that answered this one, when one was recorded. */
export function supersededBy(
  metadata: Record<string, unknown> | null | undefined,
): string | null {
  const by = metadata?.superseded_by
  return typeof by === 'string' && by.trim() !== '' ? by.trim() : null
}

/** One distinct (scope, reason) pair and how many records carry it. */
export interface IncompletenessTally {
  scope: IncompleteScope
  reason: string | null
  count: number
}

/** What a set of records says, in aggregate, about its own completeness. */
export interface IncompletenessSummary {
  /** How many records were inspected. Never inferred from anything else. */
  examined: number
  /**
   * How many of them carry at least one incompleteness stamp a later run has
   * NOT answered. Superseded records are excluded here and counted below, which
   * is what the backend census does, so a screen and a report never disagree
   * about how much of the evidence is missing.
   */
  affected: number
  /** Distinct (scope, reason) pairs, most frequent first. */
  tallies: IncompletenessTally[]
  /**
   * How many of the inspected records carried a stamp that a later run
   * answered. Reported rather than silently dropped: "this was incomplete and
   * then it was not" is a fact about how the case was worked.
   */
  superseded: number
}

/**
 * Aggregate the pair across a set of records, for a banner over a listing.
 *
 * `examined` is the size of the set actually inspected, not the size of the
 * result set on the server. A caller holding one page of a larger set must say
 * so in its own words; this function only reports what it was given, so the
 * count can never overstate what was checked.
 */
export function summarizeIncompleteness(
  records: Iterable<HasMetadata> | null | undefined,
): IncompletenessSummary {
  const tallies = new Map<string, IncompletenessTally>()
  let examined = 0
  let affected = 0
  let superseded = 0
  for (const record of records ?? []) {
    examined += 1
    const stamps = readIncompleteness(record.metadata)
    if (stamps.length === 0) continue
    if (isSuperseded(record.metadata)) {
      superseded += 1
      continue
    }
    affected += 1
    // A record short for two reasons counts once under each (UI-042), and
    // once only, however its stamps repeat a reason.
    const seen = new Set<string>()
    for (const stamp of stamps.flatMap((s) =>
      [s.reason, ...(s.additionalReasons ?? [])].map((reason) => ({
        scope: s.scope,
        reason,
      })),
    )) {
      // Written as an escape, never as a literal NUL byte: a single raw NUL in
      // this file makes grep and ripgrep classify it as binary and skip it
      // without saying so, and this is the file any future audit of "what reads
      // the stamps?" greps for first.
      const key = `${stamp.scope}\u0000${stamp.reason ?? ''}`
      if (seen.has(key)) continue
      seen.add(key)
      const existing = tallies.get(key)
      if (existing) existing.count += 1
      // Built field by field rather than spread from the stamp: a tally counts
      // a (scope, reason) pair across many records, while `detail` belongs to
      // one of them. Spreading it would attach one artifact's sentence to a
      // count that covers others.
      else
        tallies.set(key, {
          scope: stamp.scope,
          reason: stamp.reason,
          count: 1,
        })
    }
  }
  return {
    examined,
    affected,
    tallies: [...tallies.values()].sort((a, b) => b.count - a.count),
    superseded,
  }
}

/**
 * One sentence naming the scopes and reasons present, for a `title` attribute
 * or a screen-reader label where a list cannot be rendered.
 */
export function incompletenessSentence(stamps: Incompleteness[]): string {
  if (stamps.length === 0) return ''
  return stamps
    .map((stamp) => {
      const also = (stamp.additionalReasons ?? [])
        .map((reason) => `; also ${incompleteReasonLabel(reason)}`)
        .join('')
      const head = `${SCOPE_LABEL[stamp.scope]}: ${incompleteReasonLabel(stamp.reason)}${also}`
      // The parser's own words go in whole. A badge is the one place an
      // examiner may never get past, so nothing the parser said is dropped for
      // want of room.
      return stamp.detail ? `${head} — ${stamp.detail}` : head
    })
    .join('; ')
}
