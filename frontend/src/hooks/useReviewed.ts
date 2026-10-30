import { useMemo, useSyncExternalStore } from 'react'
import { apiFetch } from '../api/http'
import { formatUtc } from '../lib/format'

/**
 * The review ledger: what anybody on this case has OPENED and what anybody has
 * REVIEWED.
 *
 * ## Why the two are never one field
 *
 * Opening a row and reviewing it are different claims about different acts, and
 * the difference is the whole reason this file exists. "Opened" says a screen
 * showing this record was on an examiner's monitor. "Reviewed" says an examiner
 * deliberately asserted they had finished with it. Only the second is a
 * statement anybody would defend under oath, and folding the first into it
 * would let a scroll-past be quoted as evidence of examination. They are two
 * states all the way to the wire, they are counted separately, and every figure
 * on screen names which of the two it is counting. The reviewed set is a SUBSET
 * of the opened set, so the two are never added.
 *
 * ## Where the ledger lives
 *
 * ON THE SERVER, WITH THE CASE. It used to live in this browser's
 * localStorage, which made the answer correct for one examiner on one machine
 * — and the case outlives both. The scenario the ledger exists for is the
 * handover: examiner B inherits examiner A's case, opens it, and needs to know
 * what A actually looked at. A browser-local ledger answered that question with
 * "nothing", which is not a smaller truth than the real answer but a different
 * and false one.
 *
 * So every mark is a row in the case's `artifact_reviews` table, filed under
 * the examiner the API authenticated, and every transition is appended to the
 * case's review history — which is what keeps a review that was made and later
 * withdrawn distinguishable from one that was never made. `LEDGER_SCOPE_NOTE`
 * says all of that on screen, because a mark that other people can see and that
 * carries your name is a different thing from a private note and must not be
 * presented as one.
 *
 * ## What this module refuses to guess
 *
 * The case-wide id listing has a ceiling (100,000). Past it the server says
 * `capped`, and this module then reports every unlisted row as NOT KNOWN rather
 * than as never-opened: painting four million rows as unexamined because a list
 * stopped short is a false absence, and a false absence is the failure this
 * whole feature is meant to prevent. The same applies while the listing is in
 * flight and after it fails — `null` throughout, never `false`.
 *
 * ## Why nothing here is a percentage
 *
 * The stats endpoint does now supply an exact, named denominator — every
 * artifact recorded in the case, of every type. That population includes rows
 * nobody ever opens individually (containers, filesystems, partitions), so a
 * ratio against it is a floor on coverage rather than a measure of it. This
 * module therefore exposes counts and a NAMED population and never a ratio, and
 * leaves it to the panel to print both together or neither.
 */

/**
 * Marks the API will accept in one request (its `REVIEW_BATCH_MAX`).
 *
 * An over-long batch is refused in full and records nothing, so a client that
 * sent one would lose every opening in it with no way to learn which. Bursts
 * are split here instead.
 */
export const REVIEW_BATCH_MAX = 1000

/**
 * How long a burst of openings is allowed to gather before it is sent.
 *
 * Openings arrive in bursts — an examiner opening one conversation after
 * another — and a request per row is what drove this ledger into the browser in
 * the first place. Short enough that a mark is on the server long before the
 * examiner navigates away; long enough that a run of clicks costs one request.
 */
export const OPENING_FLUSH_MS = 300

/** Most ids one listing will return, matching the API's `REVIEW_IDS_MAX`. */
const REVIEW_IDS_MAX = 100_000

/** Most history events one per-artifact re-read will ask for. */
const HISTORY_LIMIT = 1000

/**
 * The sentence that must accompany any count taken from this ledger.
 *
 * Kept as one exported constant so the several surfaces that render a coverage
 * figure cannot each paraphrase it into something weaker. It replaces the
 * browser-local wording this note used to carry: that sentence described a real
 * limitation honestly, and the moment the ledger became shared it turned into a
 * false reassurance, which is worse than the gap it described.
 */
export const LEDGER_SCOPE_NOTE =
  'This review ledger is stored with the case on the server. Every examiner ' +
  'with access to this case sees the same marks, and each mark is filed under ' +
  'the name of the examiner who was signed in when it was made — including ' +
  'yours. Because it is shared, an empty ledger is a claim about the whole ' +
  'case — that nobody has marked anything — which is a far stronger statement ' +
  'than one screen can make on its own, so a ledger that could not be read, ' +
  'or that was listed only as far as its ceiling, says so here instead of ' +
  'showing you an empty one. Withdrawing a review removes it from the ' +
  'counts but not from the case’s review history, which records every ' +
  'opening, review and withdrawal with the examiner who made it. The ledger ' +
  'is not the audit log, and a mark is not a finding: it says what was looked ' +
  'at, not what was found.'

/**
 * The username signed in on this browser, or null if none can be read.
 *
 * Deliberately not `useAuth()`. A review mark is rendered inside table cells on
 * screens that are unit-tested without an `AuthProvider`, and `useAuth` throws
 * when there is none — a thrown hook in a row renderer takes down the whole
 * table, which is a far worse outcome than an unattributed mark. This reads the
 * same non-secret session record `AuthProvider` persists (it deliberately never
 * stores the JWT there) and treats every failure as "not known".
 *
 * It is only ever a STARTING GUESS at which examiner the server will file marks
 * under: with authentication disabled there is no session record at all and the
 * API attributes everything to `local`. The authoritative name comes back in
 * the first write's response and replaces this one — see `learnExaminer`.
 */
export function signedInExaminer(): string | null {
  try {
    const raw = localStorage.getItem('seance_session')
    if (!raw) return null
    const parsed: unknown = JSON.parse(raw)
    const username = (parsed as { username?: unknown } | null)?.username
    return typeof username === 'string' && username ? username : null
  } catch {
    return null
  }
}

/**
 * One row's standing in the ledger.
 *
 * Every state field is three-valued and the third value is load-bearing:
 * `null` means NOT KNOWN — the listing has not landed, could not be read, or
 * stopped at its ceiling before reaching this row — and a caller must render it
 * differently from `false`. See the module comment.
 */
export interface ReviewEntry {
  /** Has anybody on this case opened this record? */
  opened: boolean | null
  /** Does this record currently carry a review from anybody? */
  reviewed: boolean | null
  /**
   * Is one of those reviews yours? `null` until the server has told this
   * browser which examiner it is filing marks under.
   */
  reviewedByMe: boolean | null
  /** A write against this row is in flight. NOT a mark: nothing is recorded. */
  pending: MarkState | null
  /** Why the last write against this row did not do what it looked like. */
  error: string | null
  /**
   * WHICH examiner holds the review on this row — read only when somebody
   * asked about this row, and never guessed. See `askWhoReviewed`.
   */
  attribution: ReviewAttribution
}

/**
 * How far this row's LATEST attempt to attribute the review has got.
 *
 * Four states because three of them are not an answer of their own: nobody has
 * asked, the asking is in flight, and the asking failed are each different from
 * a reading, and a row must not render any of them as one.
 */
export type AttributionState = 'not-asked' | 'reading' | 'read' | 'unavailable'

/**
 * WHO holds the review on one row, and WHEN that was read.
 *
 * ## Why the reading carries a date
 *
 * A name on screen is an attribution, and this one is read once — when an
 * examiner asks about the row — and then held. A colleague who withdraws their
 * review afterwards does not change it. The three ways out of that were
 * weighed and only one survives cross-examination:
 *
 *  - EXPIRE IT. The name disappears, or reverts to an "ask again" control, at
 *    a moment nothing on screen accounts for. An examiner who read the name at
 *    11:02 and finds it gone at 11:32 cannot tell whether the review was
 *    withdrawn or the cache merely lapsed — and neither can the screen.
 *  - REFRESH IT. Worse: the name silently becomes a different name. That is
 *    precisely the two-answers-and-no-event failure the ledger's re-read
 *    button was built to remove, reintroduced one row at a time.
 *  - STAMP IT. The reading keeps the moment it was taken, says so beside the
 *    name, and the examiner can take another whenever they want one. The
 *    screen then never asserts more than it read: not "alice holds this
 *    review" but "at 11:02:14 UTC, this record's own history said alice held
 *    it". That sentence does not become false when alice withdraws — it stays
 *    exactly as true as it was, which is what a quoted screen has to be.
 *
 * So nothing here expires and nothing refreshes itself. `readAt` is the date
 * on the attribution, and `askWhoReviewed` may be called again — by an
 * examiner, at a moment they can name — to take a fresh one.
 *
 * ## What each field is allowed to say
 *
 * `examiners` and `readAt` describe the last reading that COMPLETED, and they
 * move together: `readAt == null` means no reading has ever completed and
 * `examiners` is then empty. They survive both a re-reading in flight and a
 * re-reading that failed, because a reading that was taken stays taken — what
 * changes is `state`, which says whether a newer answer is coming, and
 * `failedAt`, which dates an attempt that did not arrive.
 */
export interface ReviewAttribution {
  state: AttributionState
  /**
   * Examiners who held a review of this record at `readAt`, alphabetically.
   * Empty whenever `readAt` is null — an empty list is never to be read as
   * "nobody reviewed it".
   */
  examiners: string[]
  /**
   * Epoch seconds the reading in `examiners` was taken, or null if no reading
   * has completed. This is the date on the attribution: what the row knows,
   * and when it knew it.
   */
  readAt: number | null
  /**
   * Epoch seconds the most recent attempt failed, or null if it did not.
   * Distinct from `readAt`: a failed re-reading neither replaces nor discredits
   * the reading already taken, and both times are the examiner's to quote.
   */
  failedAt: number | null
}

/** Nobody has asked about this row. Shared, so an untouched row keeps identity. */
const NOT_ASKED: ReviewAttribution = {
  state: 'not-asked',
  examiners: [],
  readAt: null,
  failedAt: null,
}

export type MarkState = 'opened' | 'reviewed' | 'unreviewed'

/** One examiner's column in the case roll-up. */
export interface ReviewExaminer {
  examiner: string
  /** Artifacts this examiner opened. */
  opened: number
  /** Artifacts this examiner reviewed. A SUBSET of `opened`. */
  reviewed: number
  /** Epoch seconds. */
  firstOpenedAt: number
  /** Epoch seconds. */
  lastActivityAt: number
}

/**
 * The four responses this ledger is assembled from.
 *
 * They fail independently, they are re-read independently, and each one feeds a
 * different part of the screen — so each one carries its own reading time. A
 * panel that knew only "the ledger was read at 11:02" could not tell an
 * examiner that three of these figures are from 11:02 and the fourth from the
 * re-read they asked for at 11:41.
 */
export type LedgerPart = 'opened' | 'reviewed' | 'stats' | 'mine'

/** Every part, in the order a panel should list them. */
export const LEDGER_PARTS: readonly LedgerPart[] = [
  'opened',
  'reviewed',
  'stats',
  'mine',
]

/**
 * What each part is, in the words a panel prints.
 *
 * Kept here rather than in the panel because the retry names the parts it
 * covered and the panel names the parts it did not, and those two lists must be
 * the same words for a reader to line them up.
 */
export const LEDGER_PART_LABELS: Record<LedgerPart, string> = {
  opened: 'the case’s list of opened records',
  reviewed: 'the case’s list of reviewed records',
  stats: 'the case counts and the per-examiner roll-up',
  mine: 'which of those reviews are yours',
}

/** When one of the four was last read, and whether it last failed. */
export interface LedgerPartStatus {
  part: LedgerPart
  /** `LEDGER_PART_LABELS[part]`, carried along so a caller need not import it. */
  label: string
  /**
   * Epoch seconds this part last came back, or null if it never has. Survives
   * a later failure: what is on screen came from this reading and says so.
   */
  readAt: number | null
  /** Epoch seconds its last attempt failed, or null if that attempt succeeded. */
  failedAt: number | null
  /** Why it last failed, or null. Non-null exactly when this part is unread now. */
  error: string | null
}

/** The denominator, and the name of what it counts. */
export interface ReviewPopulation {
  total: number
  name: string
  label: string
  /**
   * True when the population counts rows nobody opens individually —
   * containers, filesystems, partitions — so a ratio against it is a FLOOR on
   * coverage rather than a measure of it.
   */
  includesNonReviewableRows: boolean
  exact: boolean
}

/**
 * The ledger's actions, for callers that hold no subscription.
 *
 * Three writes and one narrow read: `askWhoReviewed` reads one row's history,
 * and it lives here rather than in a hook because it must not cost a
 * subscription. Everything in here is bound to one case and is called, never
 * watched — a component that only records openings has no business being woken
 * when somebody else's row is marked.
 */
export interface ReviewLedgerWriter {
  /**
   * Record that a screen showing `id` was opened, batching with any other
   * openings in the same burst. Idempotent within a session, and idempotent on
   * the server: the FIRST opening is the one kept, because "when did this
   * examiner first see it" is the question a handover asks.
   */
  markOpened: (id: string) => void
  /** Record that you have finished examining `id`. Resolves when it is stored. */
  markReviewed: (id: string) => Promise<void>
  /** Withdraw YOUR review of `id`. Another examiner's review is untouched. */
  unmarkReviewed: (id: string) => Promise<void>
  /** Send any gathered openings now rather than on the timer. */
  flushOpenings: () => Promise<void>
  /**
   * Read WHICH examiners hold the review on `id`, from that row's history.
   *
   * Call this only when an examiner has actually asked about that row. It is
   * one small request per row, which is cheap once and is not cheap five
   * hundred times, so nothing here asks on behalf of a row merely because it
   * was rendered. Two asks while a reading is in flight are one request; an ask
   * once a reading has landed takes a NEW reading, with a new date, because
   * that is the only way a held attribution is ever refreshed. See
   * `ReviewAttribution`.
   */
  askWhoReviewed: (id: string) => void
}

/** The read half: the case roll-up, plus the writes. */
export interface ReviewLedger extends ReviewLedgerWriter {
  /** True once the case's listings have landed at least once. */
  loaded: boolean
  /** Why the ledger could not be read, if it could not. */
  loadError: string | null
  /** Why the last write did not do what it looked like, if it did not. */
  writeError: string | null
  /**
   * DISTINCT ARTIFACTS opened and reviewed by anybody on this case. `null`
   * where the roll-up could not be read — never 0, which would read as "nobody
   * has examined anything".
   */
  counts: { opened: number | null; reviewed: number | null }
  /** Per-examiner columns, sorted by name. The handover answer. */
  examiners: ReviewExaminer[]
  /** The named denominator, or null when the roll-up could not be read. */
  population: ReviewPopulation | null
  /**
   * True when a listing stopped at its ceiling. Rows it did not reach are
   * reported as not known, and a caller must say the list is partial rather
   * than painting them as unopened.
   */
  idsCapped: boolean
  /** Marks in flight and NOT yet recorded anywhere. */
  unrecorded: number
  /** The examiner marks are being filed under, once the server has said. */
  examiner: string | null

  /**
   * Read the case's ledger again, because the examiner asked.
   *
   * There is deliberately no automatic retry. A read that failed, then quietly
   * succeeded four minutes later, leaves a screen that said "the ledger could
   * not be read" now saying something else, with no event the examiner can
   * point to as the moment it changed — and both sentences may have been
   * quoted by then. So the recovery is something the examiner DID: they asked,
   * at a time they can state, and what came back is the answer to that asking.
   *
   * ## What it asks for
   *
   * ONLY THE PARTS THAT ARE CURRENTLY UNREAD. The ledger is four responses
   * that fail independently, and re-fetching two hundred-thousand-id listings
   * to recover a roll-up that failed on its own is a cost the examiner pays for
   * nothing — on a case at the listing ceiling it is also how a re-read becomes
   * slower than the failure it is recovering from. If nothing is failing (a
   * caller asking for a fresh reading rather than a recovery) it re-reads all
   * four.
   *
   * Narrowing is only safe because the panel says what it did: `retryScope`
   * names the parts covered and `parts` dates every one of them, so a panel can
   * never present three figures from the first read and one from the re-read as
   * though they were one reading. See `parts`.
   *
   * Concurrent calls, and a call made while the first read is still running,
   * join the read already in flight rather than starting another.
   */
  retryLoad: () => Promise<void>
  /**
   * When each of the four parts of the ledger was last read, and which are
   * unread now.
   *
   * A caller that shows a figure from a narrowed re-read MUST be able to say
   * which figures that re-read covered and which are still from an earlier
   * reading. This is that record.
   */
  parts: LedgerPartStatus[]
  /**
   * The parts the last re-read the examiner asked for covered, by label, or
   * null if they have not asked for one. Shorter than `parts` when the re-read
   * was narrowed — which is the case a panel must disclose.
   */
  retryScope: string[] | null
  /** A re-read is running. Not an answer: every count is still the old one. */
  retrying: boolean
  /**
   * Epoch seconds of the last re-read the examiner asked for that came back
   * with the ledger, or null if none has.
   */
  retriedAt: number | null
  /**
   * Epoch seconds of the last re-read the examiner asked for that ALSO failed,
   * or null if the last one did not fail. Distinct from `loadError`, which says
   * the ledger is unread and would otherwise be the same sentence after a retry
   * as before one — leaving a screen that answers an examiner's action with the
   * message it was already showing.
   */
  retryFailedAt: number | null
  /** How many re-reads the examiner asked for have failed. */
  retriesFailed: number
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

interface IdsResponse {
  ids: string[]
  total: number
  returned: number
  capped: boolean
  cap: number
}

interface StatsResponse {
  examiners: {
    examiner: string
    opened: number
    reviewed: number
    first_opened_at: number
    last_activity_at: number
  }[]
  case: { opened: number; reviewed: number }
  population: {
    total: number
    name: string
    label: string
    includes_non_reviewable_rows: boolean
    exact: boolean
  }
}

interface BatchResponse {
  examiner: string
  reviews_withdrawn: number
  rejected: string[]
}

interface HistoryResponse {
  events: {
    artifact_id: string
    examiner: string
    action: string
    at: number
  }[]
  capped: boolean
}

// ---------------------------------------------------------------------------
// The module-level store
// ---------------------------------------------------------------------------
//
// Several components on one screen read this ledger — a table's rows, the
// coverage panel above them. One store, one set of requests, one snapshot, so
// they cannot disagree about what has been marked. A hook that fetched per
// component would ask a four-million-artifact case the same question five
// hundred times per screen.

/**
 * A tri-state set membership answer.
 *
 * `set` is null while the listing has not landed or could not be read;
 * `capped` means the listing stopped short, so absence from it is not evidence
 * of anything.
 */
interface Listing {
  set: Set<string> | null
  capped: boolean
  total: number | null
}

const UNREAD: Listing = { set: null, capped: false, total: null }

/** One of the four responses: when it last came back, and how it last failed. */
interface PartRecord {
  readAt: number | null
  failedAt: number | null
  error: string | null
}

function freshParts(): Record<LedgerPart, PartRecord> {
  return {
    opened: { readAt: null, failedAt: null, error: null },
    reviewed: { readAt: null, failedAt: null, error: null },
    stats: { readAt: null, failedAt: null, error: null },
    mine: { readAt: null, failedAt: null, error: null },
  }
}

interface CaseLedger {
  caseId: string
  loading: boolean
  loaded: boolean
  loadError: string | null
  /**
   * What the ledger is currently SHORT of, as one sentence, or null when it is
   * short of nothing.
   *
   * Derived — never latched. It used to be assigned at each failure and cleared
   * nowhere, so one dropped request left "A review could not be recorded on the
   * server." standing in a `role="alert"` banner for the life of the ledger,
   * through every successful write that followed. An examiner reading that
   * banner after marking a record reviewed is being told, falsely, that the mark
   * they just made was not recorded; and the sentence sits beside whichever
   * action they took last, so it reads as a statement about that action. A
   * screen that keeps asserting a failure that has been made good is making a
   * false statement, which is the same class of defect as a wrong count.
   *
   * `loadError` was already built this way (`describeUnread`, from every part's
   * standing rather than from the last read's failures). This is the same
   * discipline applied to the write side: the three sets below hold what is
   * genuinely outstanding, each entry retires when that exact work succeeds, and
   * the sentence is rebuilt from them after every write. See `describeWriteGap`.
   */
  writeError: string | null

  /**
   * Records whose OPENING was not recorded, by id.
   *
   * Not re-queued on purpose (see `flushOpenings`), so an entry stands until the
   * examiner opens that record again and the send succeeds. Holding ids rather
   * than a count is what makes that retirement possible, and it also means two
   * failures for the same record do not read as two missing openings.
   */
  unrecordedOpenings: Set<string>
  /**
   * Records the server refused as not held in this case, by id. A standing fact
   * about the case rather than a transient failure: nothing on this screen
   * counts them, and re-trying will not change that.
   */
  notInCase: Set<string>
  /**
   * Rows whose review or withdrawal failed to reach the server, by id. Retired
   * when that row's next write succeeds, which is also when its `rowError` is
   * cleared — the two must not disagree.
   */
  unrecordedReviews: Set<string>

  /** The read in flight, so a second asker joins it rather than doubling it. */
  loadPromise: Promise<void> | null
  retrying: boolean
  retriedAt: number | null
  retryFailedAt: number | null
  retriesFailed: number
  /** Labels of what the last examiner-asked re-read covered. See `retryScope`. */
  retryScope: string[] | null

  /**
   * Per-part reading times and failures, which is what makes a NARROWED
   * re-read reportable. `load` already knew which of the four had failed
   * within one call; keeping it here is what lets the next call ask only for
   * those, and lets the panel date each figure it prints.
   */
  parts: Record<LedgerPart, PartRecord>

  /** Opened by anybody on this case. */
  caseOpened: Listing
  /** Reviewed by anybody on this case. */
  caseReviewed: Listing
  /** Reviewed by the examiner this browser is authenticated as. */
  myReviewed: Listing
  /** Which examiner `myReviewed` was fetched for, so a change forces a re-read. */
  myReviewedFor: string | null

  /**
   * What this browser has since made true, and the listings do not yet show.
   *
   * Written only AFTER the server has confirmed a transition, so nothing here
   * is optimistic. `null` in the map is an explicit "no longer known", which is
   * what a withdrawal leaves behind until the row is re-read.
   */
  openedOverride: Map<string, boolean | null>
  reviewedOverride: Map<string, boolean | null>
  mineOverride: Map<string, boolean | null>

  rowError: Map<string, string>
  pending: Map<string, MarkState>
  /** Per-row "who holds the review", for the rows somebody has asked about. */
  attribution: Map<string, ReviewAttribution>
  /**
   * The exact `rowError` sentence the attribution reading last wrote for a row.
   *
   * A notice about a reading is retired by the reading that replaces it, and
   * this is how that is done without touching a sentence somebody else wrote:
   * the note is retired only while the row is still showing this exact string,
   * so a rejected mark or a failed write standing on the row is left alone.
   * See `askWhoReviewed`.
   */
  attributionNote: Map<string, string>

  /** Openings gathered but not yet sent. */
  queue: Set<string>
  /** Openings this session has already recorded, so they are not re-sent. */
  sent: Set<string>
  timer: ReturnType<typeof setTimeout> | null
  /** Debounce for the roll-up re-read, per case. See `refreshStats`. */
  statsTimer: ReturnType<typeof setTimeout> | null
  flushing: Promise<void> | null

  examiner: string | null
  stats: StatsResponse | null

  /** Per-id snapshots, memoised so an unchanged row keeps its object identity. */
  derived: Map<string, ReviewEntry>
  snapshot: LedgerSnapshot
  subscribe: (listener: () => void) => () => void
  writer: ReviewLedgerWriter
  /** One stable `retryLoad` per case, for the same reason `writer` is stable. */
  retry: () => Promise<void>
}

/**
 * What the store publishes. `retryLoad` is excluded with the writes: it is a
 * stable function bound to the case, not a value that changes when the ledger
 * does, and rebuilding it on every publish would defeat the memoisation the
 * panel depends on.
 */
type LedgerSnapshot = Omit<
  ReviewLedger,
  keyof ReviewLedgerWriter | 'retryLoad'
>

const ledgers = new Map<string, CaseLedger>()
const listeners = new Set<() => void>()

function notify(): void {
  for (const listener of listeners) listener()
}

function ledgerOf(caseId: string): CaseLedger {
  const existing = ledgers.get(caseId)
  if (existing) return existing

  const ledger: CaseLedger = {
    caseId,
    loading: false,
    loaded: false,
    loadError: null,
    writeError: null,
    unrecordedOpenings: new Set(),
    notInCase: new Set(),
    unrecordedReviews: new Set(),
    loadPromise: null,
    retrying: false,
    retriedAt: null,
    retryFailedAt: null,
    retriesFailed: 0,
    retryScope: null,
    parts: freshParts(),
    caseOpened: UNREAD,
    caseReviewed: UNREAD,
    myReviewed: UNREAD,
    myReviewedFor: null,
    openedOverride: new Map(),
    reviewedOverride: new Map(),
    mineOverride: new Map(),
    rowError: new Map(),
    pending: new Map(),
    attribution: new Map(),
    attributionNote: new Map(),
    queue: new Set(),
    sent: new Set(),
    timer: null,
    statsTimer: null,
    flushing: null,
    examiner: null,
    stats: null,
    derived: new Map(),
    snapshot: null as unknown as LedgerSnapshot,
    subscribe: () => () => {},
    writer: null as unknown as ReviewLedgerWriter,
    retry: null as unknown as () => Promise<void>,
  }

  // Subscribing is what tells the store somebody is looking, so it is where the
  // case's listings are asked for. One stable function per case: a new one on
  // every render would make React tear the subscription down and rebuild it.
  ledger.subscribe = (listener: () => void) => {
    void ensureLoaded(ledger)
    listeners.add(listener)
    return () => {
      listeners.delete(listener)
    }
  }

  ledger.writer = {
    markOpened: (id) => markOpened(ledger, id),
    markReviewed: (id) => markReviewed(ledger, id),
    unmarkReviewed: (id) => unmarkReviewed(ledger, id),
    flushOpenings: () => flushOpenings(ledger),
    askWhoReviewed: (id) => askWhoReviewed(ledger, id),
  }
  ledger.retry = () => retryLoad(ledger)

  ledger.snapshot = buildSnapshot(ledger)
  ledgers.set(caseId, ledger)
  return ledger
}

/**
 * Forget every case's ledger and cancel anything gathered.
 *
 * Exported for tests, which need each case to start from the server's answer
 * rather than from the previous test's.
 */
export function resetReviewLedger(): void {
  for (const ledger of ledgers.values()) {
    if (ledger.timer != null) clearTimeout(ledger.timer)
    if (ledger.statsTimer != null) clearTimeout(ledger.statsTimer)
  }
  ledgers.clear()
  notify()
}

// ---------------------------------------------------------------------------
// Deriving one row's answer
// ---------------------------------------------------------------------------

function resolve(
  override: Map<string, boolean | null>,
  listing: Listing,
  id: string,
): boolean | null {
  if (override.has(id)) return override.get(id) ?? null
  if (listing.set == null) return null
  if (listing.set.has(id)) return true
  // Absence from a listing that stopped at its ceiling establishes nothing.
  return listing.capped ? null : false
}

function computeEntry(ledger: CaseLedger, id: string): ReviewEntry {
  const reviewed = resolve(ledger.reviewedOverride, ledger.caseReviewed, id)
  let reviewedByMe = resolve(ledger.mineOverride, ledger.myReviewed, id)
  // A row nobody has reviewed has not been reviewed by you either, and that
  // holds whoever you are — so this one answer does not wait on the server
  // naming the examiner. It matters: until the name is known every row would
  // otherwise read "reviewed by an examiner this browser cannot identify",
  // which is an alarming sentence to print over a case where in fact nothing
  // has been reviewed at all.
  if (reviewedByMe === null && reviewed === false) reviewedByMe = false
  return {
    opened: resolve(ledger.openedOverride, ledger.caseOpened, id),
    reviewed,
    reviewedByMe,
    pending: ledger.pending.get(id) ?? null,
    error: ledger.rowError.get(id) ?? null,
    attribution: ledger.attribution.get(id) ?? NOT_ASKED,
  }
}

function sameEntry(a: ReviewEntry, b: ReviewEntry): boolean {
  return (
    a.opened === b.opened &&
    a.reviewed === b.reviewed &&
    a.reviewedByMe === b.reviewedByMe &&
    a.pending === b.pending &&
    a.error === b.error &&
    // By identity: every attribution transition stores a NEW object, and the
    // three answerless states are shared constants, so a row nobody asked about
    // compares equal for ever and is never re-rendered on somebody else's ask.
    a.attribution === b.attribution
  )
}

function entryOf(ledger: CaseLedger, id: string): ReviewEntry {
  const cached = ledger.derived.get(id)
  if (cached) return cached
  const fresh = computeEntry(ledger, id)
  ledger.derived.set(id, fresh)
  return fresh
}

/**
 * Recompute the rows named, or every row anybody has asked about.
 *
 * An entry whose fields did not change keeps its object identity, so a row
 * subscribed to it is not re-rendered. That is what keeps one mark from costing
 * the comms table five hundred renders, and it survives a full re-read of the
 * case's listings for the same reason.
 */
function touch(ledger: CaseLedger, ids?: Iterable<string>): void {
  const targets = ids ?? [...ledger.derived.keys()]
  for (const id of targets) {
    const previous = ledger.derived.get(id)
    const fresh = computeEntry(ledger, id)
    if (previous && sameEntry(previous, fresh)) continue
    ledger.derived.set(id, fresh)
  }
}

function buildSnapshot(ledger: CaseLedger): LedgerSnapshot {
  return {
    loaded: ledger.loaded,
    loadError: ledger.loadError,
    writeError: ledger.writeError,
    counts: {
      opened: ledger.stats?.case.opened ?? null,
      reviewed: ledger.stats?.case.reviewed ?? null,
    },
    examiners: (ledger.stats?.examiners ?? []).map((e) => ({
      examiner: e.examiner,
      opened: e.opened,
      reviewed: e.reviewed,
      firstOpenedAt: e.first_opened_at,
      lastActivityAt: e.last_activity_at,
    })),
    population: ledger.stats
      ? {
          total: ledger.stats.population.total,
          name: ledger.stats.population.name,
          label: ledger.stats.population.label,
          includesNonReviewableRows:
            ledger.stats.population.includes_non_reviewable_rows,
          exact: ledger.stats.population.exact,
        }
      : null,
    idsCapped: ledger.caseOpened.capped || ledger.caseReviewed.capped,
    // `pending` alone, NOT plus `queue`. A gathered opening is entered in both
    // — `markOpened` writes the queue and the pending map together — so adding
    // them counts every waiting opening twice, and this figure is printed on
    // screen as "N marks are still being recorded". A number on screen that is
    // double the truth is exactly what the honesty conventions here forbid.
    unrecorded: ledger.pending.size,
    examiner: ledger.examiner,
    retrying: ledger.retrying,
    retriedAt: ledger.retriedAt,
    retryFailedAt: ledger.retryFailedAt,
    retriesFailed: ledger.retriesFailed,
    retryScope: ledger.retryScope,
    parts: LEDGER_PARTS.map((part) => ({
      part,
      label: LEDGER_PART_LABELS[part],
      ...ledger.parts[part],
    })),
  }
}

/** Publish everything that changed since the last call. */
function publish(ledger: CaseLedger, ids?: Iterable<string>): void {
  touch(ledger, ids)
  ledger.snapshot = buildSnapshot(ledger)
  notify()
}

// ---------------------------------------------------------------------------
// Reading the case's ledger
// ---------------------------------------------------------------------------

function reason(error: unknown): string {
  return error instanceof Error && error.message
    ? error.message
    : 'the request did not complete'
}

async function fetchIds(
  caseId: string,
  state: 'opened' | 'reviewed',
  examiner: string | null,
): Promise<Listing> {
  const page = await apiFetch<IdsResponse>(
    `/cases/${caseId}/artifact_reviews/ids`,
    {
      query: {
        state,
        limit: REVIEW_IDS_MAX,
        ...(examiner ? { examiner } : {}),
      },
    },
  )
  return {
    set: new Set(page.ids),
    capped: page.capped === true,
    total: page.total,
  }
}

async function ensureLoaded(ledger: CaseLedger): Promise<void> {
  if (ledger.loading || ledger.loaded) return
  await load(ledger)
}

/** Epoch seconds, matching every other time this ledger reports. */
function nowSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

/** The parts that are unread right now, in `LEDGER_PARTS` order. */
function unreadParts(ledger: CaseLedger): LedgerPart[] {
  return LEDGER_PARTS.filter((part) => ledger.parts[part].error != null)
}

/**
 * Read the case's ledger again because the examiner asked for it.
 *
 * Deliberately not called from anywhere but an examiner's action. See
 * `ReviewLedger.retryLoad` for why there is no timer behind this, and for why
 * it asks only for the parts that are unread.
 */
function retryLoad(ledger: CaseLedger): Promise<void> {
  // A read already in flight IS the re-read: joining it costs the server
  // nothing and cannot report a different answer from the one about to land.
  if (ledger.loadPromise) return ledger.loadPromise
  const failing = unreadParts(ledger)
  // Nothing failing means this is not a recovery but a request for a fresh
  // reading, and the honest answer to that is all four.
  const want = failing.length > 0 ? failing : [...LEDGER_PARTS]
  ledger.retryScope = want.map((part) => LEDGER_PART_LABELS[part])
  ledger.retrying = true
  // The previous attempt's outcome is cleared as the next one starts, so the
  // screen never shows "your re-read failed" beside a re-read that is running.
  ledger.retryFailedAt = null
  publish(ledger)
  return load(ledger, true, want)
}

/**
 * One read of the case's ledger at a time.
 *
 * `asked` marks a read the examiner requested, whose outcome is reported as the
 * outcome of THEIR action rather than folded into the same standing sentence.
 * `want` names the parts to ask for; the rest keep whatever reading they
 * already have, and keep the date on it.
 */
function load(
  ledger: CaseLedger,
  asked = false,
  want: readonly LedgerPart[] = LEDGER_PARTS,
): Promise<void> {
  if (ledger.loadPromise) return ledger.loadPromise
  const run = runLoad(ledger, asked, new Set(want)).finally(() => {
    if (ledger.loadPromise === run) ledger.loadPromise = null
  })
  ledger.loadPromise = run
  return run
}

/** Record that one part came back at `at`, clearing any failure it carried. */
function partRead(ledger: CaseLedger, part: LedgerPart, at: number): void {
  ledger.parts[part] = { readAt: at, failedAt: null, error: null }
}

/**
 * Record that one part did not come back.
 *
 * `readAt` is deliberately kept: whatever is on screen from that part came from
 * that reading and is still to be reported as being from it. A failure resets
 * the freshness of nothing — it only adds a dated attempt that produced no
 * answer.
 */
function partFailed(
  ledger: CaseLedger,
  part: LedgerPart,
  at: number,
  error: unknown,
): void {
  ledger.parts[part] = {
    readAt: ledger.parts[part].readAt,
    failedAt: at,
    error: reason(error),
  }
}

/**
 * The standing sentence about what could not be read, rebuilt from the parts.
 *
 * Two forms, because "the ledger could not be read" and "one of its four
 * responses could not be read" are different facts and the stronger one must
 * not be printed over the weaker. A read that lost only the opened listing
 * still has real counts to show, and saying they are not a record of anything
 * would be a false absence of its own.
 */
/**
 * What the ledger is short of on the WRITE side, as one sentence, or null.
 *
 * The counterpart of `describeUnread`, and built the same way: from what is
 * standing right now, not from the last thing that went wrong. Recomputed after
 * every write, so a failure retires exactly when the work it describes is made
 * good and not one moment sooner or later.
 *
 * Each clause names a population and what it is missing from, because the whole
 * point of the sentence is that a figure elsewhere on the screen is short by
 * this much. "Some marks failed" would leave an examiner unable to say which
 * count to distrust.
 */
function describeWriteGap(ledger: CaseLedger): string | null {
  const parts: string[] = []

  const openings = ledger.unrecordedOpenings.size
  if (openings > 0) {
    parts.push(
      `${openings} opening${openings === 1 ? ' was' : 's were'} not recorded ` +
        'on the server. They are counted nowhere on this screen; opening those ' +
        'records again will record them.',
    )
  }

  const reviews = ledger.unrecordedReviews.size
  if (reviews > 0) {
    parts.push(
      `${reviews} review${reviews === 1 ? '' : 's'} could not be written to ` +
        `the server, so ${reviews === 1 ? 'that record is' : 'those records are'} ` +
        'as they stand on the server and not as this screen was asked to leave ' +
        `${reviews === 1 ? 'it' : 'them'}. The affected row${reviews === 1 ? '' : 's'} ` +
        `say${reviews === 1 ? 's' : ''} which.`,
    )
  }

  const foreign = ledger.notInCase.size
  if (foreign > 0) {
    parts.push(
      `${foreign} record${foreign === 1 ? ' is' : 's are'} not held in this ` +
        `case, so ${foreign === 1 ? 'its mark was' : 'their marks were'} not ` +
        `recorded. No count on this screen includes ${foreign === 1 ? 'it' : 'them'}.`,
    )
  }

  return parts.length > 0 ? parts.join(' ') : null
}

function describeUnread(ledger: CaseLedger): string | null {
  const failing = unreadParts(ledger)
  if (failing.length === 0) return null
  const named = failing
    .map((part) => `${LEDGER_PART_LABELS[part]} (${ledger.parts[part].error})`)
    .join('; ')
  const anythingRead = LEDGER_PARTS.some(
    (part) => ledger.parts[part].readAt != null,
  )
  if (!anythingRead) {
    return (
      'The case’s review ledger could not be read, so what is shown here is ' +
      'not a record of what has been examined — it is a record of a question ' +
      `that was not answered (${named}).`
    )
  }
  return (
    'Part of the case’s review ledger could not be read, so what is shown ' +
    'here is not a record of what has been examined but a mixture of what ' +
    `was read and what was not. Still unread: ${named}. Anything drawn from ` +
    'those is shown as not known, never as nothing.'
  )
}

async function runLoad(
  ledger: CaseLedger,
  asked: boolean,
  want: Set<LedgerPart>,
): Promise<void> {
  ledger.loading = true
  const me = ledger.examiner ?? signedInExaminer()

  // A part not asked for is not a part that failed: it resolves to `null` and
  // every branch below leaves its listing, and its reading date, exactly as
  // they were.
  const skip = Promise.resolve(null)
  const [opened, reviewed, stats, mine] = await Promise.allSettled([
    want.has('opened') ? fetchIds(ledger.caseId, 'opened', null) : skip,
    want.has('reviewed') ? fetchIds(ledger.caseId, 'reviewed', null) : skip,
    want.has('stats')
      ? apiFetch<StatsResponse>(`/cases/${ledger.caseId}/artifact_reviews/stats`)
      : skip,
    want.has('mine') && me ? fetchIds(ledger.caseId, 'reviewed', me) : skip,
  ])

  // One moment for the whole read, so the parts that came back together are
  // dated together and a panel comparing them is comparing like with like.
  const at = nowSeconds()

  if (want.has('opened')) {
    if (opened.status === 'fulfilled') {
      ledger.caseOpened = opened.value as Listing
      ledger.openedOverride.clear()
      partRead(ledger, 'opened', at)
    } else partFailed(ledger, 'opened', at, opened.reason)
  }

  if (want.has('reviewed')) {
    if (reviewed.status === 'fulfilled') {
      ledger.caseReviewed = reviewed.value as Listing
      ledger.reviewedOverride.clear()
      // Per-row attributions were answers about the reading that has just been
      // replaced, and the overrides they wrote have just been dropped. Keeping
      // a name beside a freshly-read row would be quoting the older reading —
      // and unlike the row's own stamp, the name would then be dated by a
      // reading it did not come from.
      ledger.attribution.clear()
      partRead(ledger, 'reviewed', at)
    } else partFailed(ledger, 'reviewed', at, reviewed.reason)
  }

  if (want.has('stats')) {
    if (stats.status === 'fulfilled') {
      ledger.stats = stats.value as StatsResponse
      partRead(ledger, 'stats', at)
    } else partFailed(ledger, 'stats', at, stats.reason)
  }

  // The identity this read was made under may have been overtaken while it was
  // in flight: a write that completed meanwhile told `learnExaminer` the
  // server's name for this examiner, and it has already set `myReviewedFor`
  // and asked for the right list. Writing `me` over that would file a set read
  // for the wrong name under the right one — rows saying "reviewed — by whom
  // is not known", or another examiner's reviews labelled as this one's — and
  // then hold `learnExaminer`'s guard shut against the re-read that would have
  // corrected it (CR-033 #3). The part is left to the reading that owns it.
  const identityMoved = ledger.examiner != null && ledger.examiner !== me

  if (want.has('mine') && identityMoved) {
    // Nothing to date and nothing to fail: the answer that arrived was to a
    // question about somebody else.
  } else if (want.has('mine')) {
    if (!me) {
      // Nothing was asked, because there is nobody to ask about. That is not a
      // failure and must not be dated as a reading either: the part stays
      // unread and every row reports `reviewedByMe` as not known.
      ledger.myReviewed = UNREAD
      ledger.myReviewedFor = null
    } else if (mine.status === 'fulfilled') {
      ledger.myReviewed = mine.value as Listing
      ledger.myReviewedFor = me
      ledger.mineOverride.clear()
      partRead(ledger, 'mine', at)
    } else partFailed(ledger, 'mine', at, mine.reason)
  }

  // Built from every part's standing rather than from this read's failures, so
  // a narrowed re-read that fixed one part does not clear a sentence about
  // another part that is still unread.
  ledger.loadError = describeUnread(ledger)
  ledger.loading = false
  ledger.loaded = true
  if (asked) {
    ledger.retrying = false
    if (ledger.loadError) {
      ledger.retriesFailed += 1
      ledger.retryFailedAt = at
    } else {
      ledger.retriedAt = at
      ledger.retryFailedAt = null
    }
  }
  publish(ledger)
}

/**
 * Re-read one artifact's standing from the case's review history.
 *
 * Used where the id listings cannot answer: after a withdrawal, whether the row
 * still carries a review depends on whether ANOTHER examiner holds one, and
 * nothing in the listings this browser already has can tell. The history for a
 * single artifact is a handful of rows, so this is cheap and exact — and it is
 * the only reading that distinguishes a review that was withdrawn from one that
 * was never made.
 */
async function readRowFromHistory(
  ledger: CaseLedger,
  id: string,
): Promise<{
  opened: boolean
  reviewed: boolean
  mine: boolean | null
  /** Everyone who currently holds a review of the row, alphabetically. */
  reviewers: string[]
} | null> {
  try {
    const page = await apiFetch<HistoryResponse>(
      `/cases/${ledger.caseId}/artifact_reviews/history`,
      { query: { artifact_id: id, limit: HISTORY_LIMIT } },
    )
    // A capped history is one this reading cannot complete, and a partial
    // reading of an append-only log is not a smaller truth but a wrong one.
    if (page.capped) return null
    const held = new Map<string, boolean>()
    let opened = false
    for (const event of page.events) {
      if (event.action === 'opened' || event.action === 'reviewed')
        opened = true
      if (event.action === 'reviewed') held.set(event.examiner, true)
      if (event.action === 'review_withdrawn') held.set(event.examiner, false)
    }
    const reviewers = [...held.entries()]
      .filter(([, on]) => on)
      .map(([name]) => name)
      .sort()
    return {
      opened,
      reviewed: reviewers.length > 0,
      mine: ledger.examiner ? reviewers.includes(ledger.examiner) : null,
      reviewers,
    }
  } catch {
    return null
  }
}

/**
 * Read which examiners hold the review on one row, because somebody asked.
 *
 * ## Why this is not fetched for every rendered row
 *
 * "Reviewed by another examiner" is an unfinished sentence in a handover and a
 * useless one in a witness box: with two colleagues on a case, the per-examiner
 * panel says who worked the case and cannot say who reviewed THIS record. So
 * the name belongs on the row — but one request per row is affordable once and
 * ruinous at the comms table's five-hundred-row cap, and a table that fires
 * five hundred history reads because a pointer crossed it is a table that
 * hitches. The request is therefore made when an examiner asks about a
 * particular row and at no other time.
 *
 * ## Why the answer may overwrite the row's state
 *
 * The history is the exact and authoritative reading — it is the same source
 * `unmarkReviewed` re-reads a row from — so if it disagrees with the id
 * listings this browser loaded some time ago, the history is right. Adopting it
 * here is safe in the way an automatic refresh would not be: it happens because
 * the examiner asked about this row, at a moment they can name, which is the
 * whole distinction ITEM 1 turns on.
 *
 * ## Why asking again is allowed, and what it costs
 *
 * A reading is stamped, not expired: it stays on the row with the date it was
 * taken, for ever, and the only thing that replaces it is another ask. So a
 * name that has sat for hours is recoverable without reloading the page — and
 * it is recovered by an act with a time, not by a timer. See
 * `ReviewAttribution` for why the other two designs were rejected.
 *
 * Two asks while a reading is in flight remain ONE request: impatience is not
 * a second question, and a table is still never charged for a row nobody
 * asked about.
 *
 * ## Why the notice beside the name is dated, and does not outlive its reading
 *
 * When a reading contradicts the one the row was showing, the row says so —
 * and that sentence is a claim about a particular reading, so it carries the
 * stamp of that reading exactly as the attribution does. It said "just now"
 * once, which was true for a second and on screen for as long as the row was:
 * a later ask that found nothing changed ran no branch at all, and left the
 * row asserting that a reading taken hours ago had been taken just now.
 *
 * Two rules keep it true at every moment it is on screen. It is DATED, never
 * relative. And a reading that lands RETIRES the notice left by the reading it
 * replaces, because that notice describes a reading the row has stopped
 * showing — including the case where the new reading agrees and says nothing
 * of its own. What the row then carries is what it read and when it read it,
 * which is all it was ever entitled to claim. A reading that FAILED replaces
 * nothing and retires nothing.
 */
function askWhoReviewed(ledger: CaseLedger, id: string): void {
  if (!id) return
  const current = ledger.attribution.get(id) ?? NOT_ASKED
  // A reading already in flight IS the answer to this ask, exactly as a read
  // already running is the answer to the panel's retry.
  if (current.state === 'reading') return

  // The reading already taken is carried through unchanged, date and all: it
  // is what this row still knows until something better arrives, and blanking
  // it would leave the row unable to say anything about a review it has
  // already attributed. The previous attempt's failure is cleared as this one
  // starts, so the row never shows "could not be read" beside a reading in
  // flight.
  const reading: ReviewAttribution = {
    state: 'reading',
    examiners: current.examiners,
    readAt: current.readAt,
    failedAt: null,
  }
  ledger.attribution.set(id, reading)
  publish(ledger, [id])

  void readRowFromHistory(ledger, id).then((truth) => {
    // The case may have been dropped, or the row written to, while the history
    // was in flight; an answer about a state that no longer holds is discarded
    // rather than shown. Compared by identity against the object THIS ask
    // installed, so a later ask's reading is never overwritten by an earlier
    // one landing late.
    if (ledgers.get(ledger.caseId) !== ledger) return
    if (ledger.attribution.get(id) !== reading) return
    const at = nowSeconds()
    if (!truth) {
      // A reading that did not happen replaces nothing: the row still shows
      // the reading it showed before, so any notice about that reading is
      // still a true sentence about what is on screen and stays where it is.
      ledger.attribution.set(id, {
        state: 'unavailable',
        examiners: current.examiners,
        readAt: current.readAt,
        failedAt: at,
      })
    } else {
      ledger.attribution.set(id, {
        state: 'read',
        examiners: truth.reviewers,
        readAt: at,
        failedAt: null,
      })
      // Whatever this lane said about the reading that has just been replaced
      // is retired here, before anything new is said. That notice described
      // the reading the row was showing; the row is now showing a later one,
      // and a sentence that outlives the reading behind it is exactly how a
      // row comes to assert a recency it does not have. Retired by value, so
      // only this lane's own sentence goes: a rejected mark or a write that
      // failed is a statement about something else, and it stays put.
      retireNote(ledger, id)
      // A reading that contradicts a reading this row already showed is an
      // event, and it is said as one. An examiner may have quoted the earlier
      // name; they must be able to account for it afterwards, which means
      // seeing both names and both times rather than finding the row quietly
      // saying something else. A reading that AGREES says nothing — crying
      // change over a confirmation teaches an examiner to ignore the one that
      // is not.
      const changed =
        current.readAt != null &&
        !sameNames(current.examiners, truth.reviewers)
      const displayed = resolve(ledger.reviewedOverride, ledger.caseReviewed, id)
      if (changed) {
        // Both readings are named by the time they were taken, never by how
        // long ago they were taken. A relative phrase is true for a second and
        // quoted for an hour, and this row has already decided once — for the
        // attribution itself — that the honest form is a stamp.
        setNote(
          ledger,
          id,
          `Read again from this record’s own review history at ${utcSeconds(at)}: ${
            truth.reviewers.length > 0
              ? `it is held by ${listNames(truth.reviewers)}`
              : 'no examiner currently holds a review of it'
          }. The earlier reading on this row, taken at ` +
            `${utcSeconds(current.readAt)}, said ${
              current.examiners.length > 0
                ? listNames(current.examiners)
                : 'nobody'
            }. Both readings were true when they were taken; this screen now ` +
            'shows the later one.',
        )
      } else if (displayed === true && !truth.reviewed) {
        // The exact reading can contradict the listing this browser loaded
        // some time ago, and when it does the row stops claiming a review. It
        // says why: a row that quietly drops a claim between one glance and
        // the next leaves an examiner unable to account for what they saw
        // earlier.
        setNote(
          ledger,
          id,
          `Read from this record’s own review history at ${utcSeconds(at)}: ` +
            'no examiner currently holds a review of it. The review this row ' +
            'showed was withdrawn after the case’s listing was read, and ' +
            'nothing on this screen counts it any more.',
        )
      }
      ledger.openedOverride.set(id, truth.opened)
      ledger.reviewedOverride.set(id, truth.reviewed)
      // Only when the server has named this browser's examiner. Writing `null`
      // here would turn a known "not yours" back into "not known".
      if (truth.mine !== null) ledger.mineOverride.set(id, truth.mine)
    }
    publish(ledger, [id])
  })
}

/**
 * Put a sentence about the reading just taken on the row, and remember it.
 *
 * Remembering the exact text is what lets the NEXT reading take it back down
 * without touching a message some other path wrote into the same one-line
 * channel. See `CaseLedger.attributionNote`.
 */
function setNote(ledger: CaseLedger, id: string, note: string): void {
  ledger.rowError.set(id, note)
  ledger.attributionNote.set(id, note)
}

/**
 * Take down the sentence the last reading of this row left, if it is still up.
 *
 * Only that exact sentence: if anything else has since been written to the
 * row — a rejected mark, a write that failed — the row is saying something
 * about a different event, and that is not this lane's to clear.
 */
function retireNote(ledger: CaseLedger, id: string): void {
  const note = ledger.attributionNote.get(id)
  if (note != null && ledger.rowError.get(id) === note) {
    ledger.rowError.delete(id)
  }
  ledger.attributionNote.delete(id)
}

/** Two readings naming the same examiners, both already sorted. */
function sameNames(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((name, i) => name === b[i])
}

/** "alice", "alice and bob", "alice, bob and carol". */
function listNames(names: string[]): string {
  if (names.length <= 1) return names.join('')
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`
}

/**
 * An epoch-second stamp as this codebase renders every other forensic time:
 * UTC, explicitly labelled. A message the examiner may quote cannot carry a
 * time in whichever zone the browser happens to be in.
 */
function utcSeconds(seconds: number | null): string {
  if (seconds == null || !Number.isFinite(seconds)) return 'an unrecorded time'
  return formatUtc(new Date(seconds * 1000).toISOString())
}

// ---------------------------------------------------------------------------
// Writing marks
// ---------------------------------------------------------------------------

/**
 * Adopt the examiner name the server filed the marks under.
 *
 * The browser's session record is only a guess — with authentication disabled
 * there is none at all and the API attributes everything to `local`. Only the
 * server can say whose name is on a mark, so when it says, that answer wins and
 * "which of these reviews are mine" is re-read under the right name.
 */
function learnExaminer(ledger: CaseLedger, examiner: string): void {
  if (!examiner || ledger.examiner === examiner) return
  ledger.examiner = examiner
  if (ledger.myReviewedFor !== examiner) {
    ledger.myReviewed = UNREAD
    ledger.myReviewedFor = examiner
    void fetchIds(ledger.caseId, 'reviewed', examiner)
      .then((listing) => {
        // Only adopt it if nothing has changed identity underneath us.
        if (ledger.myReviewedFor !== examiner) return
        ledger.myReviewed = listing
        partRead(ledger, 'mine', nowSeconds())
        publish(ledger)
      })
      .catch((error: unknown) => {
        // Not knowing which reviews are yours is a smaller failure than
        // claiming the wrong ones, and it renders as "not known" — so it does
        // NOT raise `loadError`, which is a sentence about the whole ledger.
        // But it is recorded against this part, which is what puts it in the
        // panel's list of what was read and what was not, and what lets the
        // examiner ask for it again without re-fetching the case's listings.
        if (ledger.myReviewedFor !== examiner) return
        partFailed(ledger, 'mine', nowSeconds(), error)
        publish(ledger, [])
      })
  }
}

async function postMarks(
  ledger: CaseLedger,
  marks: { artifact_id: string; state: MarkState }[],
): Promise<BatchResponse> {
  const response = await apiFetch<BatchResponse>(
    `/cases/${ledger.caseId}/artifact_reviews`,
    { method: 'POST', body: { marks } },
  )
  learnExaminer(ledger, response.examiner)
  return response
}

const REJECTED_NOTE =
  'The server does not hold this artifact in this case, so the mark was not ' +
  'recorded. Nothing on this screen counts it.'

/**
 * Refresh the roll-up after a write, so the panel's counts follow the marks.
 *
 * The debounce timer is held ON THE LEDGER rather than in a module-level
 * variable. A single shared timer means a mark made in one case cancels the
 * pending refresh of another, and the case that lost its refresh goes on
 * showing counts that are behind its own ledger with nothing on screen saying
 * so — two cases open in two tabs is an ordinary way to work a handover.
 */
function refreshStats(ledger: CaseLedger): void {
  if (ledger.statsTimer != null) clearTimeout(ledger.statsTimer)
  ledger.statsTimer = setTimeout(() => {
    ledger.statsTimer = null
    void apiFetch<StatsResponse>(
      `/cases/${ledger.caseId}/artifact_reviews/stats`,
    )
      .then((stats) => {
        if (!ledgers.has(ledger.caseId)) return
        ledger.stats = stats
        // Dated, like every other reading: after a mark the roll-up really is
        // fresher than the listings beside it, and a panel that has to say
        // which of its figures came from when must be told the truth here.
        partRead(ledger, 'stats', nowSeconds())
        publish(ledger, [])
      })
      .catch(() => {
        // The counts simply stay as last read, still dated by the reading they
        // came from. They are not invented, and the marks themselves are
        // unaffected — so this is not recorded as the roll-up being unread.
      })
  }, 250)
}

function markOpened(ledger: CaseLedger, id: string): void {
  if (!id) return
  if (ledger.sent.has(id) || ledger.queue.has(id)) return
  ledger.queue.add(id)
  ledger.pending.set(id, 'opened')
  publish(ledger, [id])

  if (ledger.queue.size >= REVIEW_BATCH_MAX) {
    void flushOpenings(ledger)
    return
  }
  if (ledger.timer == null) {
    ledger.timer = setTimeout(() => {
      ledger.timer = null
      void flushOpenings(ledger)
    }, OPENING_FLUSH_MS)
  }
}

/**
 * Clear a row's in-flight mark, but only if it is still the mark being settled.
 *
 * `pending` holds one entry per row, and a later write on the same row
 * replaces it. The write that finishes first must therefore check that the
 * entry is still its own before clearing it, or it stands down a request that
 * is still out.
 */
function settlePending(
  ledger: CaseLedger,
  id: string,
  state: MarkState,
): void {
  if (ledger.pending.get(id) === state) ledger.pending.delete(id)
}

async function flushOpenings(ledger: CaseLedger): Promise<void> {
  if (ledger.timer != null) {
    clearTimeout(ledger.timer)
    ledger.timer = null
  }
  // One flush at a time, and a flush started while another is in flight waits
  // for it: two concurrent batches could otherwise both carry the same id.
  if (ledger.flushing) {
    const running = ledger.flushing
    await running
    if (ledger.queue.size === 0) return
  }
  if (ledger.queue.size === 0) return

  const run = (async () => {
    while (ledger.queue.size > 0) {
      const batch = [...ledger.queue].slice(0, REVIEW_BATCH_MAX)
      for (const id of batch) ledger.queue.delete(id)
      try {
        const response = await postMarks(
          ledger,
          batch.map((id) => ({ artifact_id: id, state: 'opened' as const })),
        )
        const rejected = new Set(response.rejected ?? [])
        for (const id of batch) {
          // Only the opening this batch carried is settled. A "Mark reviewed"
          // queued on the same row while the batch was in flight has replaced
          // the entry with its own, and clearing that would re-enable the
          // button while its POST is still out — a second click then files a
          // second assertion about one record (CR-033 #9).
          settlePending(ledger, id, 'opened')
          if (rejected.has(id)) {
            ledger.rowError.set(id, REJECTED_NOTE)
            ledger.notInCase.add(id)
            // Whatever it is, it is not an unrecorded opening: it is a record
            // this case does not hold, and the two are counted separately.
            ledger.unrecordedOpenings.delete(id)
            continue
          }
          ledger.sent.add(id)
          ledger.openedOverride.set(id, true)
          // This opening IS on the server now, so any earlier failure to record
          // it has been made good and stops being said.
          ledger.unrecordedOpenings.delete(id)
          ledger.notInCase.delete(id)
        }
        ledger.writeError = describeWriteGap(ledger)
        refreshStats(ledger)
      } catch (error) {
        for (const id of batch) {
          settlePending(ledger, id, 'opened')
          // Not re-queued. A silent retry loop would either succeed unseen or
          // spin, and either way the examiner would never learn that the ledger
          // is short of what they actually opened. Held by id so that opening
          // the record again retires exactly this entry, and so that two
          // failures for one record are not counted as two missing openings.
          ledger.unrecordedOpenings.add(id)
        }
        ledger.writeError = describeWriteGap(ledger)
        // The cause belongs on the sentence too, but only while it is the most
        // recent one: it is appended here rather than stored, so it cannot
        // outlive the gap it explains.
        if (ledger.writeError) {
          ledger.writeError += ` The last attempt failed with: ${reason(error)}.`
        }
      }
      publish(ledger, batch)
    }
  })()

  ledger.flushing = run
  try {
    await run
  } finally {
    if (ledger.flushing === run) ledger.flushing = null
  }
}

async function markReviewed(ledger: CaseLedger, id: string): Promise<void> {
  if (!id) return
  ledger.rowError.delete(id)
  // A retry of this row supersedes whatever the last attempt on it said. The
  // ledger-wide sentence is rebuilt from what stands, in the `finally` below,
  // so it can never describe a failure this write has already made good.
  ledger.unrecordedReviews.delete(id)
  // Any read of who holds this review was an answer about the row as it stood
  // before this write, so it is dropped rather than left standing beside a row
  // it no longer describes — and so is anything that reading said. See
  // `askWhoReviewed`.
  ledger.attribution.delete(id)
  ledger.attributionNote.delete(id)
  ledger.pending.set(id, 'reviewed')
  publish(ledger, [id])

  try {
    const response = await postMarks(ledger, [
      { artifact_id: id, state: 'reviewed' },
    ])
    if ((response.rejected ?? []).includes(id)) {
      ledger.rowError.set(id, REJECTED_NOTE)
      ledger.notInCase.add(id)
    } else {
      ledger.notInCase.delete(id)
      // Only now, with the server's answer in hand. An optimistic mark rolled
      // back on failure leaves one committed frame in which a review that does
      // not exist was on screen, and that frame is quotable.
      ledger.sent.add(id)
      ledger.openedOverride.set(id, true)
      ledger.reviewedOverride.set(id, true)
      ledger.mineOverride.set(id, true)
    }
    refreshStats(ledger)
  } catch (error) {
    ledger.rowError.set(
      id,
      `This review was not recorded (${reason(error)}), so nothing on this ` +
        'screen counts it. Try again.',
    )
    ledger.unrecordedReviews.add(id)
  } finally {
    settlePending(ledger, id, 'reviewed')
    // Rebuilt from what stands, on success as well as on failure: this is the
    // point at which a write that succeeded retires the sentence its earlier
    // attempt put on the screen.
    ledger.writeError = describeWriteGap(ledger)
    publish(ledger, [id])
  }
}

async function unmarkReviewed(ledger: CaseLedger, id: string): Promise<void> {
  if (!id) return
  ledger.rowError.delete(id)
  ledger.unrecordedReviews.delete(id)
  ledger.attribution.delete(id)
  ledger.attributionNote.delete(id)
  ledger.pending.set(id, 'unreviewed')
  publish(ledger, [id])

  try {
    const response = await postMarks(ledger, [
      { artifact_id: id, state: 'unreviewed' },
    ])
    const notHeld = (response.rejected ?? []).includes(id)
    // The server has just answered about this record either way, so whatever it
    // says supersedes what the last answer said.
    if (notHeld) ledger.notInCase.add(id)
    else ledger.notInCase.delete(id)

    if (notHeld) {
      ledger.rowError.set(id, REJECTED_NOTE)
    } else if (response.reviews_withdrawn === 0) {
      // Nothing of yours was there to withdraw, so the review the row carries
      // belongs to somebody else. Saying so beats a control that appears to do
      // nothing, which an examiner reads as a broken screen.
      ledger.mineOverride.set(id, false)
      ledger.rowError.set(
        id,
        'Nothing was withdrawn: you had not recorded a review of this record. ' +
          'The review it carries was made by another examiner, and only they ' +
          'can withdraw it.',
      )
    } else {
      ledger.mineOverride.set(id, false)
      // Whether the row still carries a review now depends on whether another
      // examiner holds one, which nothing already loaded can answer. Until the
      // re-read lands the honest answer is "not known", not "no".
      ledger.reviewedOverride.set(id, null)
      const truth = await readRowFromHistory(ledger, id)
      if (truth) {
        ledger.openedOverride.set(id, truth.opened)
        ledger.reviewedOverride.set(id, truth.reviewed)
        ledger.mineOverride.set(id, truth.mine)
      } else {
        ledger.rowError.set(
          id,
          'Your review was withdrawn. Whether another examiner still has this ' +
            'record marked reviewed could not be re-read, so its state is ' +
            'shown as not known rather than guessed.',
        )
      }
    }
    refreshStats(ledger)
  } catch (error) {
    ledger.rowError.set(
      id,
      `This review was not withdrawn (${reason(error)}), so it still stands. ` +
        'Try again.',
    )
    ledger.unrecordedReviews.add(id)
  } finally {
    settlePending(ledger, id, 'unreviewed')
    ledger.writeError = describeWriteGap(ledger)
    publish(ledger, [id])
  }
}

// ---------------------------------------------------------------------------
// The hooks
// ---------------------------------------------------------------------------

/**
 * The four writes bound to one case, without a subscription.
 *
 * One object per case, kept for the life of the ledger, because a stable
 * identity is what lets a component depend on it without rebuilding an effect
 * on every render. A component that only ever WRITES has no reason to be woken
 * when somebody else's row is marked, and before this existed the comms table's
 * conversation link held a subscription for exactly that reason.
 */
export function reviewLedgerWriter(caseId: string): ReviewLedgerWriter {
  return ledgerOf(caseId).writer
}

/** `reviewLedgerWriter` as a hook. Does not subscribe and never re-renders. */
export function useReviewLedgerWriter(caseId: string): ReviewLedgerWriter {
  return reviewLedgerWriter(caseId)
}

/**
 * One row's entry, and nothing else.
 *
 * The subscription is per row but the SNAPSHOT is the row's own memoised entry,
 * which `touch` carries across unchanged for every id whose answer did not
 * move. So a mark on one row wakes every row's listener — a `Map.get` each,
 * which is not a cost anybody can see — while React re-renders only the row
 * whose entry actually became a different object. A row reading the whole
 * roll-up instead, as `useReviewLedger` does, re-renders on every mark made
 * anywhere; at the comms table's five-hundred-row cap that is five hundred
 * renders for one click.
 */
export function useReviewEntry(caseId: string, id: string): ReviewEntry {
  const ledger = ledgerOf(caseId)
  return useSyncExternalStore(
    ledger.subscribe,
    () => entryOf(ledger, id),
    () => entryOf(ledger, id),
  )
}

/**
 * The case's review roll-up, and the writes.
 *
 * For the panel, which counts the whole case. A table's rows must use
 * `useReviewEntry` instead.
 */
export function useReviewLedger(caseId: string): ReviewLedger {
  const ledger = ledgerOf(caseId)
  const snapshot = useSyncExternalStore(
    ledger.subscribe,
    () => ledger.snapshot,
    () => ledger.snapshot,
  )
  return useMemo(
    () => ({ ...snapshot, ...ledger.writer, retryLoad: ledger.retry }),
    [snapshot, ledger.writer, ledger.retry],
  )
}

/**
 * Send every case's gathered openings now.
 *
 * Exported for the page-hide handler below, and for tests that would otherwise
 * be waiting on a timer.
 */
export async function flushReviewLedger(): Promise<void> {
  await Promise.all([...ledgers.values()].map((ledger) => flushOpenings(ledger)))
}

// An examiner who closes the tab mid-burst would otherwise lose whatever was
// still inside the gathering window, and lose it with nothing on screen to say
// so — the one behaviour this module does not permit anywhere else.
//
// This is best effort and is stated as such: a request started as the document
// goes away may not complete, and if it does not there is no longer a screen to
// report it on. What it buys is that the window in which an opening can be lost
// is the length of one request rather than the length of the timer. `pagehide`
// rather than `unload` because a page entering the back/forward cache fires it
// and never fires `unload` at all.
if (typeof window !== 'undefined') {
  window.addEventListener('pagehide', () => {
    void flushReviewLedger()
  })
}
