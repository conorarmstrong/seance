import type {
  EvidenceGrade,
  StageEnvelope,
  StageFailure,
  StageRecord,
} from './api'
import type { ParsedRecord } from '../analysis/api'
import { formatCount } from '../../lib/format'

/**
 * Pure wire → view-model transforms for the memory section.
 *
 * Everything here is a function of its arguments, so the rules an examiner
 * depends on — how a row is graded, when a count is a floor, when a cross-view
 * cell means "not seen" versus "never looked" — are unit-testable without a
 * DOM. Getting one of these wrong is not cosmetic: it makes an uncertain
 * finding read as a certain one.
 *
 * The analysis emits **tagged fields** rather than plain values: a PID is
 * `{kind:"known",value:4}`, or `{kind:"not_declared",member:"UniqueProcessId"}`
 * when this kernel build has no such member, or `{kind:"unavailable",detail:…}`
 * when the bytes could not be read. Flattening those three into one blank is
 * the exact defect this module refuses to commit, so decoding keeps them apart
 * and every renderer prints a different word for each.
 */

// ── Tagged fields ───────────────────────────────────────────────────────────

/** Why a field carries no value. Distinct claims, never merged. */
export type FieldAbsence =
  | 'not_applicable'
  | 'not_declared'
  | 'unavailable'
  | 'not_recorded'
  | 'not_stated'
  | 'implausible'
  | 'malformed'
  | 'none'

/** A value the analysis either read, or explained the absence of. */
export type Field<T> =
  | { known: true; value: T }
  | { known: false; reason: FieldAbsence; detail: string }

const ABSENCE_WORD: Record<FieldAbsence, string> = {
  not_applicable: 'not applicable',
  not_declared: 'no such field on this build',
  unavailable: 'unreadable',
  not_recorded: '—',
  not_stated: '—',
  implausible: 'implausible value',
  malformed: 'malformed',
  none: 'none',
}

const ABSENCE_MEANING: Record<FieldAbsence, string> = {
  not_applicable:
    'This field does not apply to this row. Its absence says nothing was missed.',
  not_declared:
    'The kernel build running on this machine has no such structure member, so there was never a value to read.',
  unavailable:
    'The bytes this field lives in could not be read. A value may exist; it could not be recovered.',
  not_recorded:
    'The field held zero, which for this field means the event did not happen.',
  not_stated:
    'This record carries no such field at all. Nothing was read and nothing was claimed: the question is unanswered here, which is not the same as the analysis having established there is nothing to report.',
  implausible:
    'The stored value is not a valid one for this field. It is kept rather than dropped, because a nonsensical value is itself evidence.',
  malformed:
    'The producer sent a shape this client does not recognise, so nothing can be asserted about the value.',
  none:
    'The analysis established that there is nothing here to name — the object carries no name, or no file is mapped into this range. That is a finding about the thing itself, not a gap in the evidence.',
}

/** The word shown in a cell for an absent value. Never a blank. */
export function fieldWord(reason: FieldAbsence): string {
  return ABSENCE_WORD[reason]
}

/** The sentence shown on hover, explaining what the absence does and does not mean. */
export function fieldMeaning(reason: FieldAbsence): string {
  return ABSENCE_MEANING[reason]
}

function absent<T>(reason: FieldAbsence, detail = ''): Field<T> {
  return { known: false, reason, detail }
}

function asObject(raw: unknown): Record<string, unknown> | null {
  return raw != null && typeof raw === 'object' && !Array.isArray(raw)
    ? (raw as Record<string, unknown>)
    : null
}

/**
 * Decode one tagged field.
 *
 * A shape this client does not recognise decodes to `malformed`, never to a
 * value and never to a plain blank: an unknown envelope means the producer and
 * this client disagree, and pretending to have read a value would be the worst
 * of the three outcomes.
 */
export function readField<T>(
  raw: unknown,
  isValue: (candidate: unknown) => candidate is T,
): Field<T> {
  const object = asObject(raw)
  if (object == null) return absent<T>('malformed', 'field was not an object')
  const kind = object.kind
  switch (kind) {
    case 'known': {
      const value = object.value
      return isValue(value)
        ? { known: true, value }
        : absent<T>('malformed', 'value had an unexpected type')
    }
    case 'not_applicable':
      return absent<T>('not_applicable')
    case 'not_declared':
      return absent<T>(
        'not_declared',
        typeof object.member === 'string' ? object.member : '',
      )
    case 'unavailable':
      return absent<T>(
        'unavailable',
        typeof object.detail === 'string' ? object.detail : '',
      )
    default:
      return absent<T>('malformed', `unknown field kind ${String(kind)}`)
  }
}

const isNumber = (candidate: unknown): candidate is number =>
  typeof candidate === 'number' && Number.isFinite(candidate)
const isString = (candidate: unknown): candidate is string =>
  typeof candidate === 'string'
const isBoolean = (candidate: unknown): candidate is boolean =>
  typeof candidate === 'boolean'

/**
 * The `kind` tag of a tagged envelope, or null when there is not one.
 *
 * Exported so a renderer that says something specific about one kind — the
 * volatile-hive badge — reads the producer's own word rather than inferring it
 * from a rendered string.
 */
export function wireKind(raw: unknown): string | null {
  const object = asObject(raw)
  return typeof object?.kind === 'string' ? object.kind : null
}

/** The explanation an envelope carries for having no value. */
function absenceDetail(object: Record<string, unknown>): string {
  if (typeof object.detail === 'string') return object.detail
  if (typeof object.member === 'string') return object.member
  const incomplete = asObject(object.incomplete)
  if (incomplete == null) return ''
  const reason = typeof incomplete.reason === 'string' ? incomplete.reason : ''
  const detail = typeof incomplete.detail === 'string' ? incomplete.detail : ''
  return [reason, detail].filter((part) => part !== '').join(': ')
}

function textValue(value: unknown, kind: string): Field<string> {
  return typeof value === 'string' && value !== ''
    ? { known: true, value }
    : absent<string>('malformed', `a ${kind} envelope carried no text`)
}

/**
 * Decode a text value out of any envelope the memory analysis emits.
 *
 * The analysis does not have one text envelope, it has several: the generic
 * `Field<String>` (`{kind:"known", value}`), a handle's name
 * (`{kind:"name", name}` / `{kind:"unnamed"}`), a VAD's mapped file
 * (`{kind:"name", name}` / `{kind:"no_mapped_file"}`) and a hive's name
 * (`{kind:"path", text, source}` / `{kind:"no_backing_file"}`). Some producers
 * additionally emit a flat string alias beside the envelope.
 *
 * Every one of those used to be read with a plain-string accessor, which
 * returns null for an object — so a handle table full of recovered file paths,
 * a DLL list, a service list and the hive list all rendered "not recorded" on
 * every row (B8-037). "Not recorded" is a claim: it says the analysis looked
 * and wrote nothing down, which is the opposite of what happened.
 *
 * One decoder for the whole vocabulary is deliberate. A per-page decoder is a
 * per-page opportunity to miss a kind, and the failure mode is silent. An
 * envelope this function does not know decodes to `malformed`, which renders as
 * a word an examiner can query, never as an absence.
 */
export function readWireText(raw: unknown): Field<string> {
  if (typeof raw === 'string') {
    // An empty string is the producer having written nothing here. It is NOT
    // `not_recorded`, whose sentence is written for a zero FILETIME ("the event
    // did not happen") and would be a claim about the machine that an empty
    // string cannot support.
    return raw === ''
      ? absent<string>('not_stated')
      : { known: true, value: raw }
  }
  const object = asObject(raw)
  if (object == null) {
    return absent<string>('malformed', 'the value was neither text nor an envelope')
  }
  const kind = typeof object.kind === 'string' ? object.kind : null
  switch (kind) {
    case 'known':
      return textValue(object.value, kind)
    case 'name':
      return textValue(object.name, kind)
    case 'path':
      return textValue(object.text, kind)
    case 'unnamed':
    case 'no_mapped_file':
    case 'no_backing_file':
      return absent<string>('none', absenceDetail(object))
    case 'not_applicable':
      return absent<string>('not_applicable', absenceDetail(object))
    case 'not_declared':
      return absent<string>('not_declared', absenceDetail(object))
    case 'unavailable':
      return absent<string>('unavailable', absenceDetail(object))
    default:
      return absent<string>('malformed', `unknown envelope kind ${String(object.kind)}`)
  }
}

/**
 * The first of several keys that decodes to a value, else the first decoded
 * absence.
 *
 * Producers rename keys between analysis versions and some emit both a
 * structured field and a flat alias. Falling back on absence rather than on
 * "key missing" keeps the reason from the envelope that actually spoke: a
 * record whose only name field is `unavailable` must not be reported as though
 * no name field existed.
 */
export function readWireTextOf(
  data: Record<string, unknown> | null | undefined,
  keys: string[],
): Field<string> {
  let firstAbsence: Field<string> | null = null
  for (const key of keys) {
    if (data == null || !(key in data)) continue
    const field = readWireText(data[key])
    if (field.known) return field
    firstAbsence ??= field
  }
  return firstAbsence ?? absent<string>('not_stated', '')
}

/**
 * The last path component of a decoded text field, keeping every absence
 * exactly as it was: a name that could not be read has no leaf either, and must
 * not become one.
 */
export function fieldLeaf(field: Field<string>): Field<string> {
  if (!field.known) return field
  const leaf = field.value.split(/[\\/]/).pop()
  return leaf ? { known: true, value: leaf } : field
}

/** Decode a numeric tagged field. */
export const readNumberField = (raw: unknown): Field<number> =>
  readField<number>(raw, isNumber)

/** Decode a text tagged field. */
export const readTextField = (raw: unknown): Field<string> =>
  readField<string>(raw, isString)

/** Decode a boolean tagged field. */
export const readBoolField = (raw: unknown): Field<boolean> =>
  readField<boolean>(raw, isBoolean)

/**
 * Decode a `ProcessTime`.
 *
 * The distinction that matters: a zero FILETIME is `not_recorded`, which for an
 * exit time means the process was still running. Converting it would date every
 * running process to 1601-01-01, and a reader who sees that column populated
 * will reasonably conclude the process had exited.
 */
export function readTimeField(raw: unknown): Field<string> {
  // A key that is not in the record at all is not a malformed value. The Linux
  // task list carries no creation or exit time -- the kernel's task_struct is
  // not where those live -- and rendering that as "malformed" told an examiner
  // the evidence was corrupt on all 133 rows. Absent and unparseable are
  // different claims, so only a value that is present and the wrong shape is
  // called malformed.
  if (raw == null) return absent<string>('not_applicable')
  const object = asObject(raw)
  if (object == null) return absent<string>('malformed', 'time was not an object')
  switch (object.kind) {
    case 'at':
      return typeof object.rfc3339 === 'string'
        ? { known: true, value: object.rfc3339 }
        : absent<string>('malformed', 'a time with no rfc3339 form')
    case 'not_recorded':
      return absent<string>('not_recorded')
    case 'implausible':
      return absent<string>(
        'implausible',
        typeof object.raw === 'string' ? object.raw : '',
      )
    case 'unavailable':
      return absent<string>(
        'unavailable',
        typeof object.detail === 'string' ? object.detail : '',
      )
    case 'not_applicable':
      return absent<string>('not_applicable')
    default:
      return absent<string>('malformed', `unknown time kind ${String(object.kind)}`)
  }
}

/** Read a plain string out of a metadata blob, or null. */
export function blobString(
  data: Record<string, unknown> | null | undefined,
  key: string,
): string | null {
  const value = data?.[key]
  return typeof value === 'string' && value !== '' ? value : null
}

/** Read a plain number out of a metadata blob, or null. */
export function blobNumber(
  data: Record<string, unknown> | null | undefined,
  key: string,
): number | null {
  const value = data?.[key]
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

/** Read a plain boolean out of a metadata blob. Null means "not stated". */
export function blobBool(
  data: Record<string, unknown> | null | undefined,
  key: string,
): boolean | null {
  const value = data?.[key]
  return typeof value === 'boolean' ? value : null
}

/**
 * Read an array of objects out of a metadata blob, keeping the count of
 * entries that were present but not objects.
 *
 * The array can hold something this code cannot read — a null, a bare string, a
 * nested array. Dropping those quietly turns a floor into a total: the page
 * shows "N processes" when the stage carried more, and an examiner has no way
 * to tell the difference. The caller decides how to surface it; what it must
 * not do is disappear.
 */
export function blobRowsCounted(
  data: Record<string, unknown> | null | undefined,
  key: string,
): { rows: Record<string, unknown>[]; dropped: number } {
  const value = data?.[key]
  if (!Array.isArray(value)) return { rows: [], dropped: 0 }
  const rows: Record<string, unknown>[] = []
  let dropped = 0
  for (const entry of value) {
    if (entry != null && typeof entry === 'object' && !Array.isArray(entry)) {
      rows.push(entry as Record<string, unknown>)
    } else {
      dropped += 1
    }
  }
  return { rows, dropped }
}

/**
 * Read an array of objects out of a metadata blob.
 *
 * Use [`blobRowsCounted`] where the number of rows is shown to an examiner;
 * this discards the count of unreadable entries.
 */
export function blobRows(
  data: Record<string, unknown> | null | undefined,
  key: string,
): Record<string, unknown>[] {
  return blobRowsCounted(data, key).rows
}

/** Read an array of strings out of a metadata blob. */
export function blobStrings(
  data: Record<string, unknown> | null | undefined,
  key: string,
): string[] {
  const value = data?.[key]
  if (!Array.isArray(value)) return []
  return value.filter(isString)
}

// ── Confidence ──────────────────────────────────────────────────────────────

/** Which enumeration produced a row. */
export type Derivation = 'linked' | 'scanned' | 'inferred' | 'carved'

/** What could not be read behind a row. */
export interface Incomplete {
  reason: string
  detail: string | null
}

/**
 * The confidence axes a row carries.
 *
 * Every field is nullable on purpose: a row that arrives without one is graded
 * down, never assumed clean.
 */
export interface RecordConfidence {
  derivation: Derivation | null
  /** Cross-view presence vector: which strategies saw this row. */
  sources: string[] | null
  incomplete: Incomplete | null
  symbol_confidence: 'verified' | 'unverified' | null
  /** The weakest grade on the profile every value here was translated through. */
  profile_evidence: EvidenceGrade | null
}

/**
 * The single grade shown on every memory-derived row, weakest axis wins.
 *
 * `linked` is a kernel list walk with clean reads, verified symbols and a
 * confirmed profile; `scanned` was found in pool memory that may have been
 * freed and reused, or rests on a profile fact nobody confirmed; `partial` hit
 * a read hole or a cap; `approximate` was decoded with symbols that passed
 * nothing that could fail but proved nothing either; `unreliable` is carved
 * with no corroboration, or decoded with no admitted symbol table at all —
 * including any row that arrives without confidence metadata.
 */
export type ConfidenceLevel =
  | 'linked'
  | 'scanned'
  | 'partial'
  | 'approximate'
  | 'unreliable'

/** Weakest-wins ordering. Higher is weaker. */
const LEVEL_RANK: Record<ConfidenceLevel, number> = {
  linked: 0,
  scanned: 1,
  partial: 2,
  approximate: 3,
  unreliable: 4,
}

/** Badge tone per level, using the existing `.badge` vocabulary. */
export const LEVEL_TONE: Record<ConfidenceLevel, string> = {
  linked: 'badge badge-ok',
  scanned: 'badge',
  partial: 'badge badge-accent',
  approximate: 'badge badge-accent',
  unreliable: 'badge badge-danger',
}

/** One line of the confidence popover. */
export interface ConfidenceReason {
  axis: 'derivation' | 'corroboration' | 'reads' | 'symbols' | 'profile'
  label: string
  detail: string
}

export interface ConfidenceVerdict {
  level: ConfidenceLevel
  reasons: ConfidenceReason[]
  /** Full-sentence label so colour and shape are never the only channel. */
  ariaLabel: string
}

const DERIVATION_DETAIL: Record<Derivation, string> = {
  linked:
    'Found by walking a kernel structure. The kernel itself still points at this row.',
  scanned:
    'Found by scanning memory for a pool tag, not by walking a kernel list. It may belong to a terminated object whose memory has been freed and partly reused.',
  inferred:
    'Not read directly. This row was derived from other structures, so it asserts less than one that was read.',
  carved:
    'Recovered from unallocated bytes by signature. Nothing in the kernel refers to it.',
}

const EVIDENCE_DETAIL: Record<EvidenceGrade, string> = {
  confirmed:
    'The address translation this row was read through was taken from a kernel structure and then confirmed by using it.',
  validated:
    'The address translation this row was read through was derived by scanning and then checked against something independent.',
  scanned:
    'The address translation this row was read through was derived by scanning, with no independent check. Everything downstream inherits that.',
  supplied:
    'The address translation this row was read through was supplied by the examiner rather than discovered from the image.',
}

/** Human phrase for an incompleteness, falling back to the raw reason. */
export function incompleteLabel(incomplete: Incomplete): string {
  const map: Record<string, string> = {
    read_hole: 'a range of bytes is not present in the image',
    not_acquired: 'bytes in this range were never written to the capture',
    paged_out: 'bytes in this range were paged out at acquisition',
    never_ram: 'this range is device memory and was never RAM',
    cap_reached: 'a safety cap stopped enumeration',
    unmapped:
      'this range was never mapped, so nothing could have been stored there',
    unvalidated:
      'these bytes came from a codepath never checked against ground truth, so treat them as unverified',
    truncated: 'a safety cap stopped enumeration',
    unreadable: 'a structure could not be read',
    unreadable_fields: 'some fields of this row could not be read',
    stage_incomplete: 'the stage that produced this row did not finish',
  }
  const base = map[incomplete.reason] ?? incomplete.reason
  return incomplete.detail ? `${base} (${incomplete.detail})` : base
}

/**
 * Grade one row from its confidence axes.
 *
 * Fails closed in both directions that matter. A row with no confidence block
 * at all is `unreliable`, because "the producer told us nothing" must never
 * render like "the producer told us it was clean". A `carved` row with fewer
 * than two corroborating sources is `unreliable` even when every other axis is
 * clean, because a signature match on freed memory is not an enumeration.
 */
export function deriveConfidence(
  confidence: RecordConfidence | null | undefined,
): ConfidenceVerdict {
  if (confidence == null) {
    return {
      level: 'unreliable',
      reasons: [
        {
          axis: 'derivation',
          label: 'not stated',
          detail:
            'This row arrived without confidence metadata, so nothing is known about how it was produced. It is graded unreliable rather than assumed sound.',
        },
      ],
      ariaLabel:
        'confidence unreliable: this row carries no confidence metadata',
    }
  }

  const reasons: ConfidenceReason[] = []
  let level: ConfidenceLevel = 'linked'
  const weaken = (next: ConfidenceLevel) => {
    if (LEVEL_RANK[next] > LEVEL_RANK[level]) level = next
  }

  const derivation = confidence.derivation
  const sources = confidence.sources ?? []
  if (derivation == null) {
    weaken('unreliable')
    reasons.push({
      axis: 'derivation',
      label: 'not stated',
      detail:
        'The producer did not say how this row was enumerated, so it cannot be trusted as a list walk.',
    })
  } else {
    reasons.push({
      axis: 'derivation',
      label: derivation,
      detail: DERIVATION_DETAIL[derivation],
    })
    if (derivation === 'scanned' || derivation === 'inferred') weaken('scanned')
    if (derivation === 'carved') {
      weaken(sources.length >= 2 ? 'scanned' : 'unreliable')
    }
  }

  reasons.push({
    axis: 'corroboration',
    label:
      confidence.sources == null
        ? 'not stated'
        : `${sources.length} source${sources.length === 1 ? '' : 's'}`,
    detail:
      confidence.sources == null
        ? 'The producer listed no enumeration sources for this row.'
        : sources.length === 0
          ? 'No enumeration strategy claims this row.'
          : `Seen by: ${sources.join(', ')}.`,
  })

  if (confidence.incomplete != null) {
    weaken('partial')
    reasons.push({
      axis: 'reads',
      label: 'incomplete',
      detail: `Some of the bytes behind this row could not be read: ${incompleteLabel(confidence.incomplete)}. Any count derived from it is a floor.`,
    })
  } else {
    reasons.push({
      axis: 'reads',
      label: 'complete',
      detail: 'Every byte this row was decoded from was present in the image.',
    })
  }

  const symbols = confidence.symbol_confidence
  if (symbols === 'verified') {
    reasons.push({
      axis: 'symbols',
      label: 'verified',
      detail:
        'Structure offsets came from a symbol table that passed every admission gate.',
    })
  } else if (symbols === 'unverified') {
    weaken('approximate')
    reasons.push({
      axis: 'symbols',
      label: 'unverified',
      detail:
        'The symbol table failed nothing, but nothing proved it either. Offsets may not match the kernel that produced these bytes.',
    })
  } else {
    weaken('unreliable')
    reasons.push({
      axis: 'symbols',
      label: 'none',
      detail:
        'No admitted symbol table stands behind this row, so the structure layout used to decode it is unproven.',
    })
  }

  const evidence = confidence.profile_evidence
  if (evidence == null) {
    weaken('approximate')
    reasons.push({
      axis: 'profile',
      label: 'not stated',
      detail:
        'The producer did not say how the image profile behind this row was established, so the translation it was read through is ungraded.',
    })
  } else {
    if (evidence === 'scanned' || evidence === 'supplied') weaken('scanned')
    reasons.push({
      axis: 'profile',
      label: evidence,
      detail: EVIDENCE_DETAIL[evidence],
    })
  }

  return {
    level,
    reasons,
    ariaLabel: `confidence ${level}: ${reasons.map((r) => `${r.axis} ${r.label}`).join(', ')}`,
  }
}

/** Stage keys whose records were read by walking a kernel structure. */
const STAGE_DERIVATION: Record<string, Derivation> = {
  processes: 'linked',
  process_tree: 'inferred',
  pool_scan: 'scanned',
  cross_view: 'inferred',
  kernel_modules: 'linked',
  network: 'scanned',
  services: 'scanned',
  registry_hives: 'linked',
  tampering: 'inferred',
  // Which VAD a thread's start address lands in, and what that range maps:
  // each range is linked, but "this thread runs injected code" is inferred.
  suspicious_threads: 'inferred',
  // The unloaded-driver table is reached through a symbol-named pointer and
  // read at declared offsets, so it is linked. When a group that scans lands,
  // that group's records name their own derivation — see `recordConfidence`.
  tamper_checks: 'linked',
  // A job's members come from walking `_EJOB.ProcessListHead`, and the jobs
  // themselves from each process's own `Job` pointer: both linked.
  jobs: 'linked',
  // The drivers come from a pool sweep; their devices and the attachment stacks
  // above them are pointer chains read from those objects. The rows rest on the
  // sweep, so the weaker of the two grades is the honest one.
  device_tree: 'scanned',
  vad: 'linked',
  handles: 'linked',
  dlls: 'linked',
  // A pattern match is bytes found by scanning, and nothing about the pointer
  // chain that planned where to scan makes the match itself anything stronger.
  // The allocation the row names IS linked -- it came from the VAD tree -- but
  // the row's own claim is the scan's.
  pattern_scan: 'scanned',
}

function isEvidenceGrade(value: unknown): value is EvidenceGrade {
  return (
    value === 'confirmed' ||
    value === 'validated' ||
    value === 'scanned' ||
    value === 'supplied'
  )
}

/**
 * Build the confidence block for a row from the stage record that carried it.
 *
 * The analysis stamps `profile_evidence` and `symbols_verified` onto every
 * record it emits, and marks a record `content_complete: false` when its stage
 * stopped short. Those are read here rather than guessed. The derivation comes
 * from the stage that produced the record — a pool scan is a scan whatever the
 * row looks like — unless the record names its own, which some stages do when a
 * single stage mixes methods.
 */
export function recordConfidence(
  stage: string,
  data: Record<string, unknown> | null | undefined,
  options: { sources?: string[] | null; rowIncomplete?: Incomplete | null } = {},
): RecordConfidence {
  const named = blobString(data, 'derivation')
  const derivation =
    named === 'linked' || named === 'scanned' || named === 'inferred' || named === 'carved'
      ? named
      : (STAGE_DERIVATION[stage] ?? null)

  const verified = blobBool(data, 'symbols_verified')
  const complete = blobBool(data, 'content_complete')
  const stageIncomplete: Incomplete | null =
    complete === false
      ? {
          reason: 'stage_incomplete',
          detail: blobString(data, 'incomplete_detail'),
        }
      : null

  return {
    derivation,
    sources: options.sources ?? null,
    incomplete: options.rowIncomplete ?? stageIncomplete,
    symbol_confidence:
      verified === true ? 'verified' : verified === false ? 'unverified' : null,
    profile_evidence: isEvidenceGrade(data?.profile_evidence)
      ? data.profile_evidence
      : null,
  }
}

/** Outcome of the symbol admission gates. */
export type SymbolState = 'verified' | 'unverified' | 'rejected' | 'no_match'

/**
 * Normalise the symbol state the profile records.
 *
 * The analysis serialises it with Rust's `Debug` formatting, so `Verified` and
 * `NoMatch` are what arrive on the wire. Returns null for anything else,
 * including absence — and null is rendered as "not stated", never as verified.
 */
export function readSymbolState(value: unknown): SymbolState | null {
  if (typeof value !== 'string') return null
  switch (value.toLowerCase().replace(/[^a-z]/g, '')) {
    case 'verified':
      return 'verified'
    case 'unverified':
      return 'unverified'
    case 'rejected':
      return 'rejected'
    case 'nomatch':
      return 'no_match'
    default:
      return null
  }
}

// ── Lens status ─────────────────────────────────────────────────────────────

/**
 * What a lens should render, decided once so no page decides it differently.
 *
 * `not_run` and `empty` are the pair this whole surface exists to keep apart.
 * `undetermined` is a third state the API can report on a per-process view: the
 * search stopped at a cap before it had seen everything, so neither "this
 * process has none" nor "the stage did not run" is true.
 */
export type LensStatus =
  | { kind: 'not_run'; message: string }
  | { kind: 'undetermined'; message: string }
  | { kind: 'empty' }
  | { kind: 'partial'; message: string }
  | { kind: 'complete' }

/** One sentence naming every failure record attached to a stage. */
export function failureSummary(failures: StageFailure[]): string {
  if (failures.length === 0) return ''
  return failures
    .map((failure) => {
      const where = failure.stage ?? failure.stages?.join(', ') ?? 'a stage'
      const who =
        failure.pid != null
          ? ` (pid ${failure.pid}${failure.process_name ? ` ${failure.process_name}` : ''})`
          : ''
      return `${where}${who}: ${failure.failure ?? 'no reason recorded'}`
    })
    .join('; ')
}

/** Assemble the sentence explaining why a stage's counts are a floor. */
function floorReason(envelope: StageEnvelope): string {
  const parts: string[] = []
  if (envelope.records_truncated) {
    parts.push(
      `only ${formatCount(envelope.records_returned)} of ${formatCount(envelope.record_count)} records were returned`,
    )
  }
  if (envelope.rows_incomplete > 0) {
    const one = envelope.rows_incomplete === 1
    parts.push(
      `${formatCount(envelope.rows_incomplete)} row${one ? '' : 's'} declared ${one ? 'itself' : 'themselves'} incomplete`,
    )
  }
  if (envelope.rows_completeness_ungraded > 0) {
    const one = envelope.rows_completeness_ungraded === 1
    parts.push(
      `${formatCount(envelope.rows_completeness_ungraded)} row${one ? '' : 's'} did not say whether ${one ? 'it was' : 'they were'} complete`,
    )
  }
  if (envelope.failures.length > 0) {
    parts.push(failureSummary(envelope.failures))
  }
  if (envelope.failures_truncated) {
    parts.push('the failure list itself was truncated')
  }
  return parts.length > 0
    ? parts.join('; ')
    : 'the server marked this stage a floor without naming the cap'
}

/**
 * End a status message with a full stop, unless it already ends in one.
 *
 * These messages come from several sources: some are whole sentences from the
 * server, others are assembled clause lists like `floorReason`. Callers render
 * them immediately before another sentence, so an unterminated one runs the two
 * together — "1 row declared itself incomplete No signal is listed" was on
 * screen. Adding the stop unconditionally would double it on the sources that
 * already have one.
 */
export function terminated(message: string): string {
  const trimmed = message.trimEnd()
  if (trimmed.length === 0) return trimmed
  return /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`
}

/**
 * Decide what a lens renders from the stage envelope.
 *
 * Never collapses "did not run" into "found nothing": an empty table after a
 * crashed scanner says the machine was clean, and that would be a lie of
 * omission.
 *
 * `decodedRows` is how many rows the lens actually decoded from the envelope.
 * Pass it whenever the lens renders rows: a stage that ran and found nothing
 * still emits a record, so without it a `complete` verdict would be returned for
 * a lens with nothing to show and the honest empty state would never render.
 */
export function envelopeStatus(
  envelope: StageEnvelope | null | undefined,
  decodedRows?: number | null,
): LensStatus {
  if (envelope == null) {
    return {
      kind: 'not_run',
      message:
        'The server did not say whether this analysis ran. Its results cannot be interpreted, and an empty list here would mean nothing.',
    }
  }
  if (envelope.status === 'did_not_run' || envelope.status === 'failed') {
    const failures = failureSummary(envelope.failures)
    return {
      kind: 'not_run',
      message: failures
        ? `${envelope.status_meaning} ${failures}`
        : envelope.status_meaning,
    }
  }
  if (envelope.status === 'not_determined') {
    return { kind: 'undetermined', message: envelope.status_meaning }
  }
  if (envelope.count_is_floor) {
    return { kind: 'partial', message: floorReason(envelope) }
  }
  // `record_count` counts the stage's *records*, not its findings. A stage that
  // ran and found nothing still emits one — a `MemoryNetwork` record whose
  // `connections` array is empty. So emptiness is judged on the rows a lens
  // decoded, which is what `decodedRows` carries, and callers that render rows
  // always pass it.
  //
  // Without `decodedRows`, a `record_count` of 0 is NOT "found nothing". The API
  // derives `stage_ran` as `record_count > 0` and reports a stage with no records
  // as `did_not_run`, handled above; and the plugin emits a result or a failure
  // record for every stage it attempts. So a zero count reaching here means the
  // envelope is self-contradictory — a status that is not `did_not_run` over a
  // stage that left nothing behind — and the one thing it cannot support is the
  // affirmative claim that the stage looked and found nothing. Keeping "did not
  // run" and "found nothing" apart is the whole reason this function exists, so
  // an envelope that cannot tell us which is reported as neither.
  if (decodedRows == null && envelope.record_count === 0) {
    return {
      kind: 'not_run',
      message:
        'This analysis reported no records at all, so nothing here can be read as a finding. An empty result and an analysis that never produced one are not the same, and this envelope cannot tell them apart.',
    }
  }
  const empty = decodedRows != null && decodedRows === 0
  return empty ? { kind: 'empty' } : { kind: 'complete' }
}

// ── Processes ───────────────────────────────────────────────────────────────

/** One process, decoded from a `MemoryProcessList` record. */
export interface ProcessRow {
  /** Stable React key: the record it came from plus its kernel address. */
  key: string
  recordId: string
  /** Kernel address of the `_EPROCESS`, hex. */
  address: string
  /** Which walk reached it: `forward`, `backward`. */
  direction: string
  pid: Field<number>
  ppid: Field<number>
  name: Field<string>
  threads: Field<number>
  handles: Field<number>
  sessionId: Field<number>
  createTime: Field<string>
  exitTime: Field<string>
  hasExited: boolean
  /** Fields of this row that could not be read. Never silently dropped. */
  unreadableFields: string[]
  notes: string[]
  confidence: RecordConfidence
}

/**
 * Suffix added to an address that JSON could not carry exactly.
 *
 * Exported so a renderer can explain the words rather than leave an examiner
 * guessing what they qualify.
 */
export const ROUNDED_ADDRESS_SUFFIX = ' (may be rounded)'

/**
 * Sentence explaining the suffix, for a `title` on the cell that carries it.
 */
export const ROUNDED_ADDRESS_MEANING =
  'This address is larger than 2^53, and JSON numbers are IEEE doubles, so its low bits may have been rounded in transit. Do not quote it as an exact pointer without checking the record.'

/**
 * Hex form of a number the API sent as a JSON number.
 *
 * An examiner reads this as a kernel pointer, so the one thing it must never do
 * is print a rounded value as though it were exact. Every x64 kernel address is
 * larger than `Number.MAX_SAFE_INTEGER`, and the analysis serialises addresses
 * as JSON numbers, so such a value arrives as a double whose low bits may
 * already have been lost. A wrong answer here looks like an `_EPROCESS` address
 * quoted in a report that is off by up to a kilobyte, so anything outside the
 * exactly-representable range is rendered with an explicit qualifier instead.
 */
export function toHex(value: number | null | undefined): string | null {
  if (value == null || !Number.isFinite(value)) return null
  if (value < 0) return null
  const hex = `0x${Math.trunc(value).toString(16)}`
  return Number.isSafeInteger(value) ? hex : `${hex}${ROUNDED_ADDRESS_SUFFIX}`
}

/** A `{:#x}`-formatted address as the analysis writes its `*_hex` siblings. */
const HEX_LITERAL = /^0[xX][0-9a-fA-F]+$/

/**
 * A kernel address, preferring the exact `*_hex` sibling over the JSON number.
 *
 * The analysis emits every address twice: as a number, which is what a
 * programmatic consumer reads, and as a `<key>_hex` string, which is the only
 * form that survives the wire intact. `serde_json` encodes `u64` as an IEEE
 * double and every x64 kernel address exceeds 2^53, so the numeric form is
 * silently rounded — by up to about a kilobyte at `0xffff_8000_0000_0000`. An
 * `_EPROCESS` address quoted in a report from the rounded value is simply the
 * wrong address.
 *
 * So the string is read first and rendered exactly, with no qualifier: once the
 * sibling is in hand "(may be rounded)" is no longer true, and a caveat on a
 * value that does not need one teaches an examiner to discount the ones that
 * do. The number is the fallback for a record written before the sibling
 * existed, and it keeps its qualifier. A sibling present but not a hex literal
 * is not trusted and not used — the numeric path, which states its own doubt,
 * is safer than a string this code cannot parse.
 */
export function hexAddress(
  data: Record<string, unknown> | null | undefined,
  key: string,
): string | null {
  const sibling = data?.[`${key}_hex`]
  if (typeof sibling === 'string' && HEX_LITERAL.test(sibling.trim())) {
    return sibling.trim()
  }
  return toHex(blobNumber(data, key))
}

/**
 * Decode every process out of a `processes` stage envelope.
 *
 * `sources` is threaded in from the cross-view lens so a row's corroboration
 * reflects what other strategies said, not just the walk that produced it.
 */
export function readProcesses(
  envelope: StageEnvelope | null | undefined,
  sourcesForPid?: (pid: number | null) => string[] | null,
): ProcessRow[] {
  const out: ProcessRow[] = []
  for (const record of envelope?.records ?? []) {
    // Windows calls this array `processes`; the Linux tier walks `init_task`
    // and calls it `tasks`. Reading only the first showed a Linux capture's 133
    // processes as none at all -- and "0 processes" from a stage the coverage
    // table said had run is a claim, not a gap.
    const processes = blobRowsCounted(record.data, 'processes')
    const tasks = blobRowsCounted(record.data, 'tasks')
    const rows = [...processes.rows, ...tasks.rows]
    const unreadableEntries = processes.dropped + tasks.dropped
    for (const raw of rows) {
      const pid = readNumberField(raw.pid)
      const unreadable = blobStrings(raw, 'unreadable_fields')
      const address = hexAddress(raw, 'address')
      out.push({
        // The exact hex is the stable identity here: two processes rounded to
        // the same double would otherwise collide on one React key.
        key: `${record.id}:${address ?? out.length}`,
        recordId: record.id,
        address: address ?? 'address not recorded',
        direction: blobString(raw, 'direction') ?? 'not stated',
        pid,
        ppid: readNumberField(raw.ppid),
        // `image_file_name` on Windows, `comm` on Linux: the same field, named
        // after the structure member each kernel keeps it in.
        name: readTextField(raw.image_file_name ?? raw.comm),
        threads: readNumberField(raw.threads),
        handles: readNumberField(raw.handles),
        sessionId: readNumberField(raw.session_id),
        createTime: readTimeField(raw.create_time),
        exitTime: readTimeField(raw.exit_time),
        hasExited: blobBool(raw, 'has_exited') === true,
        unreadableFields: unreadable,
        notes: blobStrings(raw, 'notes'),
        confidence: recordConfidence(
          envelope?.stage ?? 'processes',
          record.data,
          {
            sources: sourcesForPid
              ? sourcesForPid(pid.known ? pid.value : null)
              : null,
            rowIncomplete:
              unreadable.length > 0
                ? { reason: 'unreadable_fields', detail: unreadable.join(', ') }
                : null,
          },
        ),
      })
    }

    // An entry the stage carried but this code could not read is still an
    // entry. Showing one fewer row and no explanation would make the count a
    // floor presented as a total, which is the claim this table exists not to
    // make — the same reason a row keeps `unreadableFields` rather than
    // dropping the field.
    for (let index = 0; index < unreadableEntries; index += 1) {
      out.push({
        key: `${record.id}:unreadable:${index}`,
        recordId: record.id,
        address: 'address not recorded',
        direction: 'not stated',
        pid: readNumberField(undefined),
        ppid: readNumberField(undefined),
        name: readTextField(undefined),
        threads: readNumberField(undefined),
        handles: readNumberField(undefined),
        sessionId: readNumberField(undefined),
        createTime: readTimeField(undefined),
        exitTime: readTimeField(undefined),
        hasExited: false,
        unreadableFields: ['the whole entry'],
        notes: [
          'this entry of the stage’s process array was not an object, so nothing could be read from it',
        ],
        confidence: recordConfidence(envelope?.stage ?? 'processes', record.data, {
          sources: null,
          rowIncomplete: {
            reason: 'unreadable_entry',
            detail: 'the entry was not an object',
          },
        }),
      })
    }
  }
  return out
}

/** How a parent edge was established, or why none was drawn. */
export type ParentLinkKind =
  | 'confirmed'
  | 'unverified'
  | 'ambiguous'
  | 'orphaned'
  | 'cycle'
  | 'root'
  | 'unknown'

/** One node of the tree the analysis built, decoded from `MemoryProcessTree`. */
export interface TreeNodeRow {
  address: string
  pid: number | null
  ppid: number | null
  parent: number | null
  children: number[]
  depth: number
  link: ParentLinkKind
  linkDetail: string
}

/**
 * Decode the tree the *analysis* built.
 *
 * The tree is taken from the server rather than rebuilt here on purpose: the
 * analysis knows which edges it could confirm and which it refused to draw, and
 * re-deriving parentage from PIDs in the browser would silently reinstate every
 * edge the analysis declined — including the ones a reused PID makes false.
 */
export function readTreeNodes(
  envelope: StageEnvelope | null | undefined,
): TreeNodeRow[] {
  const out: TreeNodeRow[] = []
  for (const record of envelope?.records ?? []) {
    for (const raw of blobRows(record.data, 'nodes')) {
      const link = asObject(raw.link)
      const kind = typeof link?.kind === 'string' ? link.kind : 'unknown'
      out.push({
        address: hexAddress(raw, 'address') ?? 'address not recorded',
        pid: blobNumber(raw, 'pid'),
        ppid: blobNumber(raw, 'ppid'),
        parent: blobNumber(raw, 'parent'),
        children: Array.isArray(raw.children)
          ? raw.children.filter(isNumber)
          : [],
        depth: blobNumber(raw, 'depth') ?? 0,
        link: isParentLinkKind(kind) ? kind : 'unknown',
        linkDetail: typeof link?.detail === 'string' ? link.detail : '',
      })
    }
  }
  return out
}

function isParentLinkKind(value: string): value is ParentLinkKind {
  return [
    'confirmed',
    'unverified',
    'ambiguous',
    'orphaned',
    'cycle',
    'root',
    'unknown',
  ].includes(value)
}

/** What each parent-edge kind means for the row that carries it. */
export const PARENT_LINK_MEANING: Record<ParentLinkKind, string> = {
  confirmed:
    'The edge to the parent rests on more than a matching process id.',
  unverified:
    'The edge rests on a matching process id alone. Process ids are reissued, so this parentage is not established.',
  ambiguous:
    'More than one recovered process could be the parent, so no single edge is drawn.',
  orphaned:
    'No recovered process carries this parent id. No edge is drawn to a guess.',
  cycle:
    'Following the parent ids led back to this process. A smeared parent id can do that, so the edge is refused.',
  root: 'This process has no parent in the recovered set.',
  unknown:
    'The analysis did not say what this edge rests on, so it is treated as unestablished.',
}

/**
 * Group processes into a renderable hierarchy using the analysis's own tree.
 *
 * Nodes index into the process list by position, so the two are read together
 * and nothing is matched back up by PID.
 */
export interface ProcessTreeRow {
  row: ProcessRow
  depth: number
  link: ParentLinkKind
  linkDetail: string
  childCount: number
  index: number
}

/**
 * Interleave the decoded process list with the decoded tree.
 *
 * A node whose index has no process — which a truncated list can produce — is
 * skipped rather than rendered against the wrong process, because attaching one
 * process's facts to another's row is the worst outcome available here.
 */
export function buildProcessRows(
  processes: ProcessRow[],
  nodes: TreeNodeRow[],
): ProcessTreeRow[] {
  if (nodes.length === 0) {
    return processes.map((row, index) => ({
      row,
      depth: 0,
      link: 'unknown' as ParentLinkKind,
      linkDetail: '',
      childCount: 0,
      index,
    }))
  }
  const roots: number[] = []
  for (let index = 0; index < nodes.length; index++) {
    if (nodes[index].parent == null) roots.push(index)
  }
  const out: ProcessTreeRow[] = []
  const seen = new Set<number>()
  const emitted = new Set<number>()
  const walk = (index: number) => {
    // Bounded by `seen`: a malformed child list that points back up would
    // otherwise recurse until the stack gave out.
    if (seen.has(index)) return
    seen.add(index)
    const node = nodes[index]
    const row = processes[index]
    if (node != null && row != null) {
      emitted.add(index)
      out.push({
        row,
        depth: node.depth,
        link: node.link,
        linkDetail: node.linkDetail,
        childCount: node.children.length,
        index,
      })
    }
    for (const child of node?.children ?? []) walk(child)
  }
  for (const root of roots) walk(root)
  // Any node the roots did not reach is still evidence; append it rather than
  // dropping it, and let its own link kind explain why it stands alone.
  for (let index = 0; index < nodes.length; index++) {
    if (!seen.has(index)) walk(index)
  }
  // A process the tree never accounted for is still a process the list walk
  // recovered. It is appended flat rather than dropped: a tree record that
  // stopped short of the list record — a cap that bit one stage and not the
  // other — would otherwise remove processes from the screen entirely, and a
  // process missing from the list is the one thing this lens must never do.
  for (let index = 0; index < processes.length; index++) {
    if (emitted.has(index)) continue
    out.push({
      row: processes[index],
      depth: 0,
      link: 'unknown',
      linkDetail:
        'The tree stage produced no node for this process, so no parentage is asserted for it.',
      childCount: 0,
      index,
    })
  }
  return out
}

// ── Cross view ──────────────────────────────────────────────────────────────

/** One enumeration strategy in the cross-view matrix. */
export interface CrossviewMethod {
  key: string
  label: string
  /** False means this column is unknown for every row, not "not seen". */
  ran: boolean
  error: string | null
}

/** Presence of one process in one enumeration strategy. */
export type Presence = 'seen' | 'not_seen' | 'unknown'

/** One process's presence vector. */
export interface CrossviewRow {
  pid: number | null
  name: string | null
  seen: Record<string, boolean>
}

export interface Crossview {
  methods: CrossviewMethod[]
  rows: CrossviewRow[]
}

/**
 * Decode the cross-view stage.
 *
 * A method the record does not mention for a row is left out of `seen`, which
 * resolves to `unknown`. It is never defaulted to false: a strategy that said
 * nothing about a process is not a strategy that failed to find it.
 */
export function readCrossview(
  envelope: StageEnvelope | null | undefined,
): Crossview {
  const methods = new Map<string, CrossviewMethod>()
  const rows: CrossviewRow[] = []
  for (const record of envelope?.records ?? []) {
    for (const raw of blobRows(record.data, 'methods')) {
      const key = blobString(raw, 'key') ?? blobString(raw, 'name')
      if (key == null) continue
      methods.set(key, {
        key,
        label: blobString(raw, 'label') ?? key,
        ran: blobBool(raw, 'ran') !== false,
        error: blobString(raw, 'error'),
      })
    }
    for (const raw of blobRows(record.data, 'processes')) {
      const seen: Record<string, boolean> = {}
      const vector = asObject(raw.seen)
      for (const [key, value] of Object.entries(vector ?? {})) {
        if (typeof value === 'boolean') seen[key] = value
      }
      rows.push({
        pid: blobNumber(raw, 'pid'),
        name: blobString(raw, 'image_file_name') ?? blobString(raw, 'name'),
        seen,
      })
    }
  }
  return { methods: [...methods.values()], rows }
}

/**
 * Resolve the cross-view cell for one process and one method.
 *
 * `unknown` is not a rounding of `not_seen`. A strategy that failed tells you
 * nothing about the process; rendering that as an absence is how a cross-view
 * matrix manufactures a hidden-process finding out of a crashed scanner.
 */
export function presenceFor(
  method: CrossviewMethod,
  row: CrossviewRow | undefined,
): Presence {
  if (!method.ran) return 'unknown'
  if (row == null) return 'unknown'
  const value = row.seen[method.key]
  if (value === true) return 'seen'
  if (value === false) return 'not_seen'
  return 'unknown'
}

/** Accessible sentence for a whole presence vector. */
export function presenceLabel(
  methods: CrossviewMethod[],
  row: CrossviewRow | undefined,
): string {
  const seen: string[] = []
  const notSeen: string[] = []
  const unknown: string[] = []
  for (const method of methods) {
    const bucket = presenceFor(method, row)
    if (bucket === 'seen') seen.push(method.label)
    else if (bucket === 'not_seen') notSeen.push(method.label)
    else unknown.push(method.label)
  }
  const parts: string[] = []
  parts.push(seen.length > 0 ? `seen by ${seen.join(' and ')}` : 'seen by nothing')
  if (notSeen.length > 0) parts.push(`not seen by ${notSeen.join(' and ')}`)
  if (unknown.length > 0) parts.push(`not checked by ${unknown.join(' and ')}`)
  return parts.join('; ')
}

// ── Generic row lens ────────────────────────────────────────────────────────

/**
 * One row of a list-shaped stage (network, services, hives, handles, modules,
 * regions, tampering), kept as its raw blob plus the confidence of the record
 * that carried it.
 *
 * Deliberately not reshaped into a per-stage type: each stage's blob is defined
 * by its own analysis module, and a client-side schema for each would be a
 * second definition to drift from the first. Renderers read the keys they know
 * and say so when one is absent.
 */
export interface StageRow {
  key: string
  recordId: string
  data: Record<string, unknown>
  /**
   * The blob of the record this row was taken out of.
   *
   * A per-process stage puts the process's own identity on the record and the
   * rows inside an array on it, so a row read on its own has no idea which
   * process it belongs to. Keeping the record beside the row lets a renderer
   * attribute it without guessing — the same object when a record is itself one
   * row.
   */
  record: Record<string, unknown>
  confidence: RecordConfidence
}

/**
 * Flatten a stage envelope into rows.
 *
 * `arrayKeys` names the blob keys that hold row arrays, tried in order; the
 * first one that is present and non-empty supplies the rows. A record that
 * carries such a key but only empty arrays yields no rows at all — that is the
 * stage saying it found none, and it is a different answer from the record
 * shape below. Only when a record carries none of the keys is the record itself
 * taken as one row, because a stage that emits one object per process (a handle
 * table, a module list) is still evidence and must not vanish for want of a
 * matching key.
 */
export function readStageRows(
  envelope: StageEnvelope | null | undefined,
  arrayKeys: string[],
): StageRow[] {
  const out: StageRow[] = []
  for (const record of envelope?.records ?? []) {
    const confidence = recordConfidence(envelope?.stage ?? '', record.data)
    // Tracked separately from "did we emit rows". A row array that is present
    // and empty is the stage saying "none of these", so it must suppress the
    // record-as-one-row fallback below: letting it through would put a
    // fabricated row on screen — one connection, one service, one handle that
    // no analysis ever reported — for a stage that found nothing.
    let sawRowArray = false
    let matched = false
    for (const key of arrayKeys) {
      const raw = record.data?.[key]
      if (!Array.isArray(raw)) continue
      sawRowArray = true
      if (raw.length === 0) continue
      matched = true
      blobRows(record.data, key).forEach((row, index) => {
        out.push({
          key: `${record.id}:${key}:${index}`,
          recordId: record.id,
          data: row,
          record: record.data ?? {},
          confidence,
        })
      })
      break
    }
    if (!matched && !sawRowArray) {
      out.push({
        key: record.id,
        recordId: record.id,
        data: record.data,
        record: record.data,
        confidence,
      })
    }
  }
  return out
}

/** The tampering stage's signals, and the records this client could not read. */
export interface TamperingSignals {
  rows: StageRow[]
  /**
   * Records (or processes inside one) whose shape this client did not
   * recognise. Never folded into "no signals": a record nobody could read is an
   * unanswered question, and the findings lens states an exculpatory conclusion
   * when its list is empty.
   */
  unreadable: number
}

/**
 * The tampering signals in a `tampering` envelope.
 *
 * This stage is NOT list-shaped like the others, and `readStageRows` cannot
 * reach it. `TamperingScan::to_json` emits ONE record for the whole scan —
 * `{ examined: [ { pid, image_file_name, signals: [ … ] } ], skipped, … }` — so
 * the signals sit two levels down and the process they belong to is on the
 * level between. Read with `readStageRows(env, ['signals', …])` the record
 * matched no row key at all and fell through to the record-as-one-row path:
 * every capture, tampered or clean, produced exactly one card reading "Signal
 * with no title" with no subject, and no real signal was ever displayed. A
 * fabricated finding on the one lens whose output is an accusation.
 *
 * The process object is kept as the row's `record` so a card can attribute the
 * signal — the signal itself carries no pid, by design, because the analysis
 * writes it once per process rather than once per signal.
 *
 * A record that carries no `examined` array is counted as unreadable rather
 * than skipped. Silently dropping it would put the shape mismatch behind the
 * lens's "the scan ran and recorded nothing" copy, which is the one sentence
 * this function exists to keep honest.
 */
export function readTamperingSignals(
  envelope: StageEnvelope | null | undefined,
): TamperingSignals {
  const rows: StageRow[] = []
  let unreadable = 0
  for (const record of envelope?.records ?? []) {
    const confidence = recordConfidence(envelope?.stage ?? '', record.data)
    const examined = record.data?.examined
    if (!Array.isArray(examined)) {
      unreadable += 1
      continue
    }
    examined.forEach((entry, processIndex) => {
      const process = asObject(entry)
      const signals = process?.signals
      if (process == null || !Array.isArray(signals)) {
        unreadable += 1
        return
      }
      signals.forEach((raw, signalIndex) => {
        const data = asObject(raw)
        if (data == null) {
          unreadable += 1
          return
        }
        rows.push({
          key: `${record.id}:examined:${processIndex}:signals:${signalIndex}`,
          recordId: record.id,
          data,
          record: process,
          confidence,
        })
      })
    })
  }
  return { rows, unreadable }
}

/** Rows plus the per-record blobs, for lenses that need both. */
export function stageRecords(
  envelope: StageEnvelope | null | undefined,
): StageRecord[] {
  return envelope?.records ?? []
}

// ── Formatting ──────────────────────────────────────────────────────────────

/**
 * Format a total that some rows weaken.
 *
 * `41` where three rows were scan-only renders `41 (3 scanned)`. A bare `41`
 * would present a mixed-reliability aggregate as a uniform one, which is
 * exactly the failure a memory tool must not commit.
 */
export function formatQualifiedCount(
  total: number,
  qualifiers: { count: number; label: string }[],
): string {
  const parts = qualifiers
    .filter((q) => q.count > 0)
    .map((q) => `${formatCount(q.count)} ${q.label}`)
  const head = formatCount(total)
  return parts.length > 0 ? `${head} (${parts.join(', ')})` : head
}

/** Format an address for display; a missing address is a dash, never `0x0`. */
export function formatAddress(value: string | null | undefined): string {
  if (!value) return '—'
  return value.startsWith('0x') ? value : `0x${value}`
}

/** Parse an ISO timestamp to epoch ms, or null. Never throws, never guesses. */
export function parseTime(iso: string | null | undefined): number | null {
  if (!iso) return null
  const ms = Date.parse(iso)
  return Number.isFinite(ms) ? ms : null
}

/**
 * Format a timestamp for display.
 *
 * A missing time is a dash. It is never rendered as an epoch, and a zero
 * FILETIME arrives as an absent field rather than as `1601-01-01`.
 */
export function formatTime(iso: string | null | undefined): string {
  const ms = parseTime(iso)
  if (ms == null) return '—'
  return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z')
}

/** Render a decoded field as text, with a distinct word per kind of absence. */
export function fieldText(field: Field<string | number>): string {
  if (field.known) return String(field.value)
  return fieldWord(field.reason)
}

/** Render a decoded time field, formatted when known. */
export function timeText(field: Field<string>): string {
  return field.known ? formatTime(field.value) : fieldWord(field.reason)
}

/** Hover text explaining a field's value or the reason it has none. */
export function fieldTitle(field: Field<string | number>): string {
  if (field.known) return ''
  const meaning = fieldMeaning(field.reason)
  return field.detail ? `${meaning} (${field.detail})` : meaning
}

// ── Lifetime lanes ──────────────────────────────────────────────────────────

/** Position of a lifetime bar on the shared boot → acquisition axis. */
export interface LanePlacement {
  leftPercent: number
  widthPercent: number
  /** True when the row's start is unknown and the bar is anchored to the axis. */
  startUnknown: boolean
  /** True when the row is still present at the end of the axis. */
  openEnded: boolean
}

/** The axis a lane chart is drawn against, and whether it is the real one. */
export interface LaneAxis {
  startMs: number
  endMs: number
  /**
   * True when both bounds were known. When false the axis was derived from the
   * rows themselves and the label must say so, because "started near the left
   * edge" then means something different.
   */
  bounded: boolean
  label: string
}

const MIN_BAR_PERCENT = 0.6

/**
 * Choose the axis for a lane chart.
 *
 * Prefers real bounds. Falls back to the span of the rows themselves and marks
 * the axis unbounded, so the chart labels itself honestly instead of implying a
 * boot time nobody established.
 */
export function laneAxis(
  boot: string | null,
  acquired: string | null,
  rowTimes: (number | null)[],
): LaneAxis | null {
  const bootMs = parseTime(boot)
  const acquiredMs = parseTime(acquired)
  if (bootMs != null && acquiredMs != null && acquiredMs > bootMs) {
    return {
      startMs: bootMs,
      endMs: acquiredMs,
      bounded: true,
      label: 'boot to acquisition',
    }
  }
  const known = rowTimes.filter((t): t is number => t != null)
  if (known.length === 0) return null
  const min = Math.min(...known)
  const max = Math.max(...known)
  return {
    startMs: min,
    endMs: max > min ? max : min + 1,
    bounded: false,
    label:
      'earliest to latest recorded time (boot and acquisition times were not established)',
  }
}

/** Place one bar on the axis, clamping to it rather than overflowing. */
export function placeOnLane(
  axis: LaneAxis,
  startMs: number | null,
  endMs: number | null,
): LanePlacement {
  const span = axis.endMs - axis.startMs
  const clamp = (value: number) => Math.min(100, Math.max(0, value))
  const toPercent = (ms: number) => clamp(((ms - axis.startMs) / span) * 100)
  const left = startMs == null ? 0 : toPercent(startMs)
  const right = endMs == null ? 100 : toPercent(endMs)
  const width = Math.max(MIN_BAR_PERCENT, right - left)
  return {
    leftPercent: left,
    widthPercent: Math.min(100 - left, width),
    startUnknown: startMs == null,
    openEnded: endMs == null,
  }
}

// ── Credentials ─────────────────────────────────────────────────────────────

/** How many credentials belong to each other capture in the case. */
export interface OtherCaptureCount {
  imageId: string
  count: number
}

/**
 * Split credential records into those attributable to the selected capture,
 * those that name no capture at all, and a tally of those belonging to other
 * captures in the same case.
 *
 * The second group is shown under a note rather than dropped: a credential
 * recovered from memory is exactly the kind of record an examiner must not lose
 * to a filter they cannot see.
 *
 * The third is counted for the same reason. Records naming another capture are
 * correctly not listed here, but silently discarding them makes a multi-capture
 * case look like a single-capture one: the examiner reads "these are the
 * credentials" with no sign that more were recovered a tab away (B4-026).
 */
export function splitCredentialsByImage(
  records: ParsedRecord[],
  imageId: string,
): {
  attributed: ParsedRecord[]
  unattributed: ParsedRecord[]
  otherCaptures: OtherCaptureCount[]
} {
  const attributed: ParsedRecord[] = []
  const unattributed: ParsedRecord[] = []
  const others = new Map<string, number>()
  for (const record of records) {
    const meta = record.metadata as Record<string, unknown>
    const named =
      typeof meta.memory_image_id === 'string'
        ? meta.memory_image_id
        : typeof meta.memory_profile_id === 'string'
          ? meta.memory_profile_id
          : record.parent_id
    if (named == null) unattributed.push(record)
    else if (named === imageId) attributed.push(record)
    else others.set(named, (others.get(named) ?? 0) + 1)
  }
  return {
    attributed,
    unattributed,
    otherCaptures: [...others.entries()]
      .map(([id, count]) => ({ imageId: id, count }))
      .sort((a, b) => b.count - a.count || a.imageId.localeCompare(b.imageId)),
  }
}

// ── Credential inventory ────────────────────────────────────────────────────

/**
 * The credential **inventory** record, decoded.
 *
 * What the stage produces is a listing, not a recovery: which credential stores
 * were resident, which local accounts the SAM names, what the LSA secrets are
 * called, how many cached domain logons are present. Nothing in it is
 * decrypted. Every count below is therefore `null` when the producer did not
 * state it, never `0` — "the SECURITY hive named no secrets" and "this record
 * does not say how many secrets there were" are different findings, and a zero
 * standing in for the second is the exact overstatement this decoder exists to
 * prevent.
 */

/** One credential hive the survey looked for, and whether it was reachable. */
export interface CredentialHiveRow {
  hive: string | null
  /** Null means the producer did not say, which is not "unavailable". */
  available: boolean | null
  binSource: string | null
  binSourceAuthoritative: boolean | null
  detail: string | null
}

/** One local account named in the SAM. The name only; no secret is read. */
export interface CredentialAccountRow {
  name: string | null
  rid: number | null
  /** Whether a second place in the hive corroborates the RID. */
  ridCorroborated: boolean | null
  lastWriteFiletime: number | null
  notes: string[]
}

/** One LSA secret. Its NAME, which is the subkey's name and is not encrypted. */
export interface CredentialSecretRow {
  name: string | null
  lastWriteFiletime: number | null
}

/** One key path the survey tried to enumerate, and what became of it. */
export interface CredentialListingRow {
  key: string | null
  complete: boolean | null
  detail: string | null
}

export interface CredentialInventory {
  recordId: string
  /** The stage's own sentence about what it did and did not do with the stores. */
  decryptionStatement: string | null
  /**
   * The producer's claim about plaintext. Only an explicit `false` is a denial;
   * `null` means the record did not state it, and `true` would mean this build
   * decrypts — which no build in the tree does, so it is surfaced rather than
   * assumed impossible.
   */
  plaintextRecovered: boolean | null
  /** How many credential VALUES the stage says it recovered. Null if unstated. */
  credentialsRecovered: number | null
  hives: CredentialHiveRow[]
  accounts: CredentialAccountRow[]
  /** The producer's own account total, which may exceed the rows it listed. */
  accountCount: number | null
  secrets: CredentialSecretRow[]
  secretCount: number | null
  cachedLogons: number | null
  listings: CredentialListingRow[]
  inventoryComplete: boolean | null
  incompleteReason: string | null
  /** True when a listing stopped at its cap, so the rows are a floor. */
  truncated: boolean | null
  /**
   * Entries in the record's own arrays that were not objects and so could not
   * be decoded. Counted rather than dropped: a silently shortened account list
   * reads as a machine with fewer accounts than it has.
   */
  undecodableEntries: number
}

/** Entries of `key` that are not decodable objects, so cannot be listed. */
function undecodableIn(
  data: Record<string, unknown> | null | undefined,
  key: string,
): number {
  const value = data?.[key]
  if (!Array.isArray(value)) return 0
  return value.length - blobRows(data, key).length
}

/**
 * Decode one `MemoryCredentials` record into the inventory the page renders.
 *
 * Nothing is defaulted. A field the producer did not send comes back `null` and
 * is rendered as "not stated", because the alternative — a zero — is a claim
 * about the machine that no analysis made.
 */
export function readCredentialInventory(
  record: ParsedRecord,
): CredentialInventory {
  const data = record.metadata as Record<string, unknown>
  return {
    recordId: record.id,
    decryptionStatement: blobString(data, 'decryption'),
    plaintextRecovered: blobBool(data, 'plaintext_recovered'),
    credentialsRecovered: blobNumber(data, 'credentials_recovered'),
    hives: blobRows(data, 'hives').map((row) => ({
      hive: blobString(row, 'hive'),
      available: blobBool(row, 'available'),
      binSource: blobString(row, 'bin_source'),
      binSourceAuthoritative: blobBool(row, 'bin_source_authoritative'),
      detail: blobString(row, 'detail'),
    })),
    accounts: blobRows(data, 'accounts').map((row) => ({
      name: blobString(row, 'name'),
      rid: blobNumber(row, 'rid'),
      ridCorroborated: blobBool(row, 'rid_corroborated'),
      lastWriteFiletime: blobNumber(row, 'last_write_filetime'),
      notes: blobStrings(row, 'notes'),
    })),
    accountCount: blobNumber(data, 'account_count'),
    secrets: blobRows(data, 'secrets').map((row) => ({
      name: blobString(row, 'name'),
      lastWriteFiletime: blobNumber(row, 'last_write_filetime'),
    })),
    secretCount: blobNumber(data, 'secret_count'),
    cachedLogons: blobNumber(data, 'cached_logons'),
    listings: blobRows(data, 'listings').map((row) => ({
      key: blobString(row, 'key'),
      complete: blobBool(row, 'complete'),
      detail: blobString(row, 'detail'),
    })),
    inventoryComplete: blobBool(data, 'inventory_complete'),
    incompleteReason:
      blobString(data, 'inventory_incomplete_reason') ??
      blobString(data, 'content_incomplete_reason'),
    truncated: blobBool(data, 'truncated'),
    undecodableEntries:
      undecodableIn(data, 'hives') +
      undecodableIn(data, 'accounts') +
      undecodableIn(data, 'secrets') +
      undecodableIn(data, 'listings'),
  }
}

/**
 * A count the producer stated, or the words for one it did not.
 *
 * The whole point: `0` is a finding and "not stated" is a hole, and a screen
 * that prints the second as the first tells an examiner the machine had no
 * cached logons when nothing counted them.
 */
export function inventoryCount(value: number | null): string {
  return value == null ? 'not stated' : formatCount(value)
}

/** 100 ns ticks between the FILETIME epoch (1601) and the Unix epoch (1970). */
const FILETIME_UNIX_OFFSET = 116_444_736_000_000_000

/**
 * Render a raw Windows FILETIME.
 *
 * A zero tick count is what the producer sends for "the key carried no last
 * write time", so it is a dash rather than `1601-01-01` — a date nobody
 * observed. A tick count that does not land in a representable date is a dash
 * for the same reason: nothing is guessed from it.
 */
export function filetimeText(ticks: number | null): string {
  if (ticks == null || ticks <= 0) return '—'
  const ms = (ticks - FILETIME_UNIX_OFFSET) / 10000
  if (!Number.isFinite(ms) || Math.abs(ms) > 8.64e15) return '—'
  return formatTime(new Date(ms).toISOString())
}
