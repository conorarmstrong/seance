import { useEffect } from 'react'
import { formatCount, formatUtc } from '../../lib/format'
import {
  LEDGER_PARTS,
  LEDGER_SCOPE_NOTE,
  useReviewEntry,
  useReviewLedger,
  useReviewLedgerWriter,
  type LedgerPartStatus,
  type ReviewEntry,
  type ReviewExaminer,
} from '../../hooks/useReviewed'
import './bookmark.css'

/**
 * The per-row half of the review ledger: has this been opened, does it carry a
 * review, and is that review yours?
 *
 * The first two are rendered as different things because they are different
 * claims. "Opened" is a faint word beside the row and nothing more — it records
 * that a screen showing this record was on someone's monitor, which is a fact
 * about attention, not about examination. "Reviewed" is a control an examiner
 * has to press, because it is the one an advocate would put to them in the
 * witness box.
 *
 * The third claim is new, and it exists because the ledger is now shared. A row
 * a COLLEAGUE reviewed reads as reviewed, but this examiner cannot withdraw it;
 * offering a control that would appear to do nothing is worse than saying whose
 * mark it is.
 *
 * And a state that has not been read is never drawn as a state that has. A row
 * still in flight, or one that fell past the listing's ceiling, says it is not
 * known — because on a shared ledger "nobody has opened this" is a claim about
 * the whole case, and it must not be manufactured out of a claim about the
 * network.
 */
export function ReviewMark({
  caseId,
  /** Artifact (or record) id the mark is against. */
  id,
  /** What the row is, named in the control's accessible label. */
  subject,
  /**
   * Record an opening as soon as this mounts. Only pass this where mounting
   * genuinely means the record was PUT IN FRONT of the examiner — an opened
   * viewer, not a row scrolled past in a table.
   */
  openedOnMount = false,
}: {
  caseId: string
  id: string
  subject: string
  openedOnMount?: boolean
}) {
  // One row's entry and the writes, rather than the whole roll-up: the comms
  // table draws up to five hundred of these, and a mark reads and writes
  // exactly one of them. Reading the roll-up here would make one click cost the
  // table five hundred renders — see `useReviewEntry`.
  const entry = useReviewEntry(caseId, id)
  const ledger = useReviewLedgerWriter(caseId)
  const { markOpened } = ledger

  useEffect(() => {
    if (openedOnMount) markOpened(id)
  }, [openedOnMount, markOpened, id])

  const busy = entry.pending != null
  const mine = entry.reviewedByMe === true
  // Pressed is a claim about THIS examiner's review, because withdrawing it is
  // what pressing the control does. A colleague's review is reported beside the
  // control rather than inside it, and an unread state is "mixed" rather than
  // "not pressed" — aria-pressed="false" would announce "not reviewed" to a
  // screen reader over a row nobody has asked about.
  const pressed: 'true' | 'false' | 'mixed' = mine
    ? 'true'
    : entry.reviewedByMe == null && entry.reviewed !== false
      ? 'mixed'
      : 'false'

  return (
    <span className="rvw">
      <button
        type="button"
        className={mine ? 'rvw-toggle reviewed' : 'rvw-toggle'}
        aria-pressed={pressed}
        aria-busy={busy || undefined}
        // Disabled only while this row's own write is in flight, so a second
        // click cannot file a second assertion about the same record.
        disabled={busy}
        aria-label={labelFor(entry, subject)}
        title={titleFor(entry)}
        onClick={() => {
          if (mine) void ledger.unmarkReviewed(id)
          else void ledger.markReviewed(id)
        }}
      >
        {busy ? '…' : mine ? '✓ Reviewed' : 'Mark reviewed'}
      </button>
      {busy && (
        <span className="rvw-opened">
          {entry.pending === 'unreviewed' ? 'withdrawing…' : 'recording…'}
        </span>
      )}
      {!busy && !mine && entry.reviewed === true && (
        <WhoReviewed
          entry={entry}
          subject={subject}
          onAsk={() => ledger.askWhoReviewed(id)}
        />
      )}
      {!busy && entry.reviewed === false && entry.opened === true && (
        <span
          className="rvw-opened"
          title="An examiner on this case has had a screen showing this record open. Opening a record is not examining it."
        >
          opened
        </span>
      )}
      {!busy && entry.reviewed == null && (
        <span
          className="rvw-opened"
          title="This record’s standing in the case’s review ledger has not been read, so nothing here says it has or has not been examined."
        >
          not known
        </span>
      )}
      {entry.error && (
        <span className="rvw-row-error" role="alert">
          {entry.error}
        </span>
      )}
    </span>
  )
}

/**
 * Whose review is on this row — said, or offered to be read, but never guessed.
 *
 * ## Why the name is on the row at all
 *
 * "Reviewed by another examiner" is the end of the sentence a screen can write
 * from the id listings alone, and it is not enough. The per-examiner table in
 * the panel answers a different question — who has worked this case — and on a
 * case with two colleagues it cannot say which of them reviewed THIS record.
 * That is the question an examiner has while they are looking at the row, and
 * the one an advocate asks about it afterwards: not "who worked the case" but
 * "who says they examined this".
 *
 * ## Why it is not fetched for every row that renders
 *
 * Each name costs one history request. That is nothing for a row somebody
 * asked about and it is five hundred requests for a table nobody has touched,
 * so the request is made on ACTIVATION — a press, by pointer or keyboard — and
 * not on hover or on focus. Hover and focus both sweep: a pointer dragged down
 * the table, or a Tab held through it, would fire a request per row and none of
 * them would be a question anybody asked. A press is unambiguous, and it is the
 * same principle the panel's re-read button rests on: the examiner did it, at a
 * moment they can name.
 *
 * ## What it never renders
 *
 * A name that has not arrived is never rendered as a name, and never as its
 * absence. The three answerless states each say what they are — nobody has
 * asked, the asking is in flight, the asking failed — because "reviewed by
 * nobody" and "reviewed by somebody whose name is still coming" are different
 * claims about a record, and only one of them can be true here.
 *
 * ## Why the name arrives with a date attached
 *
 * The reading is taken once and then held: a colleague who withdraws their
 * review afterwards does not change it, and nothing here polls to find out.
 * That is deliberate — a name that changed on its own, or vanished on an
 * expiry, would move the screen at a moment the examiner could not account for,
 * which is the failure the panel's re-read button exists to prevent. So the row
 * prints the moment the reading was taken, IN THE ROW rather than in a tooltip,
 * because a tooltip cannot be quoted and cannot be read aloud. "At 11:02:14
 * UTC this record's history said alice held the review" stays true after alice
 * withdraws; "alice holds this review" does not.
 *
 * The stamp doubles as the control that takes another reading, so an examiner
 * who wants a current answer gets one from an act of their own with a time on
 * it. See `ReviewAttribution`.
 */
function WhoReviewed({
  entry,
  subject,
  onAsk,
}: {
  entry: ReviewEntry
  subject: string
  onAsk: () => void
}) {
  const { state, examiners, readAt, failedAt } = entry.attribution

  // A reading that completed is shown whatever the latest attempt is doing:
  // it is still what this row knows, and it still says when it knew it.
  if (readAt != null && examiners.length > 0) {
    const taken = formatEpochSeconds(readAt)
    return (
      <span
        className="rvw-opened rvw-who-read"
        title={`Read from this record’s own review history, which records every review and withdrawal against it with the examiner who made it. Only ${listNames(
          examiners,
        )} can withdraw ${examiners.length === 1 ? 'that review' : 'those reviews'}; you can record your own.`}
      >
        reviewed by {listNames(examiners)}{' '}
        <button
          type="button"
          className="rvw-who rvw-who-again"
          aria-busy={state === 'reading' || undefined}
          aria-label={
            state === 'reading'
              ? `Reading again which examiner reviewed ${subject}`
              : state === 'unavailable'
                ? `Which examiner reviewed ${subject} was read at ${taken}; the later reading at ${formatEpochSeconds(
                    failedAt,
                  )} did not complete. Read it again.`
                : `Which examiner reviewed ${subject} was read at ${taken}. Read it again.`
          }
          title="This name is what the record’s history said at the time shown, not a live reading: nothing here re-reads on its own, because a name that changed with no act of yours behind it could not be accounted for afterwards. Press to take a new reading now."
          onClick={onAsk}
        >
          {state === 'reading'
            ? `read at ${taken} — reading again…`
            : state === 'unavailable'
              ? `read at ${taken} — a later reading at ${formatEpochSeconds(
                  failedAt,
                )} did not complete`
              : `read at ${taken} — read again`}
        </button>
      </span>
    )
  }

  // "another examiner" is a claim, and it is only safe once the server has
  // named the examiner this browser is filing marks under: before that, the
  // review on this row may be this examiner's own.
  const carrier =
    entry.reviewedByMe === false
      ? 'reviewed by another examiner'
      : 'reviewed — by whom is not known'

  return (
    <button
      type="button"
      className="rvw-who"
      aria-busy={state === 'reading' || undefined}
      aria-label={
        state === 'reading'
          ? `Reading which examiner reviewed ${subject}`
          : state === 'unavailable'
            ? `Which examiner reviewed ${subject} could not be read — read it again`
            : `Read which examiner reviewed ${subject}`
      }
      title={
        state === 'unavailable'
          ? 'This record’s review history could not be read, so the examiner who reviewed it is not named here. The review itself still stands.'
          : 'Reads this record’s own review history to name the examiner who reviewed it. Nothing is read until you ask: a name per row is one request per row, and a table asks about five hundred of them.'
      }
      onClick={onAsk}
    >
      {carrier}
      {state === 'reading'
        ? ' — reading who…'
        : state === 'unavailable'
          ? ' — who could not be read'
          : ' — who?'}
    </button>
  )
}

/** "alice", "alice and bob", "alice, bob and carol". */
function listNames(names: string[]): string {
  if (names.length <= 1) return names.join('')
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`
}

/**
 * The control's accessible name.
 *
 * Every variant that is not this examiner's own review begins "Mark … reviewed"
 * because that is what pressing it does; what differs is the qualification
 * after it, which is where a colleague's mark and the ledger's uncertainty are
 * stated rather than hidden.
 */
function labelFor(entry: ReviewEntry, subject: string): string {
  if (entry.pending === 'reviewed') return `Recording your review of ${subject}`
  if (entry.pending === 'unreviewed')
    return `Withdrawing your review of ${subject}`
  if (entry.pending === 'opened') return `Recording that ${subject} was opened`
  if (entry.reviewedByMe === true)
    return `Reviewed by you — withdraw the review of ${subject}`
  if (entry.reviewed === true && entry.reviewedByMe === false)
    return `Mark ${subject} reviewed (another examiner has already reviewed it)`
  if (entry.reviewed === true)
    return `Mark ${subject} reviewed (it already carries a review, by an examiner this browser has not identified)`
  if (entry.reviewed === false) return `Mark ${subject} reviewed`
  return `Mark ${subject} reviewed (its review state has not been read)`
}

const MARK_SCOPE =
  'Marks are stored with the case and are visible to every examiner who can ' +
  'open it, under the name of whoever made them.'

function titleFor(entry: ReviewEntry): string {
  if (entry.reviewedByMe === true)
    return `You recorded a review of this record. Withdrawing it leaves the opening on the record. ${MARK_SCOPE}`
  if (entry.reviewed === true && entry.reviewedByMe === false)
    return `Another examiner recorded a review of this record; only they can withdraw it. You can record your own. ${MARK_SCOPE}`
  if (entry.reviewed === true)
    return `This record carries a review, but this browser has not been told which examiner it is filing marks under, so it cannot say whether the review is yours. ${MARK_SCOPE}`
  if (entry.reviewed === false)
    return `Nobody on this case has recorded a review of this record. ${MARK_SCOPE}`
  return `Whether this record has been reviewed could not be read, so this is not a statement that it has not been. ${MARK_SCOPE}`
}

/**
 * The aggregate half: what the case's ledger holds, and who put it there.
 *
 * Deliberately not a progress bar and deliberately not a percentage. A bar has
 * one shape and it always says "this is how much of the job is done"; over a
 * case whose population the screen may not be entitled to divide by, that
 * sentence is unsupportable. Two counts, a denominator only where a caller
 * supplies and names one, and a per-examiner breakdown say exactly as much as
 * is known and no more.
 *
 * The breakdown is the reason the ledger moved to the server at all. It is the
 * handover answer — what did examiner A actually look at — and it could not be
 * asked of a ledger that lived in A's browser.
 */
export function ReviewLedgerPanel({
  caseId,
  population,
  compact = false,
}: {
  caseId: string
  /**
   * The population these counts should be read against, if the caller knows one
   * and is prepared to name it. Omit it and the panel says the denominator is
   * not stated rather than inviting the reader to supply one.
   *
   * The server now offers a case-wide total of its own, and the panel still
   * does not reach for it, because a panel does not know what page it is on. On
   * Communications the marks it counts are case-wide while the page around it
   * shows a capped slice of sixteen record types; a denominator printed there
   * would be read against the page and would be wrong. The surface that knows
   * its own scope passes a population in. Nothing else prints one.
   */
  population?: { count: number | null; noun: string }
  /**
   * Render as one line with the qualifications behind a disclosure.
   *
   * For screens where the ledger is secondary — a working table an examiner
   * came to for the evidence, not for the coverage figure — five paragraphs
   * above the page title is a real cost to the examiner with forty-five
   * minutes. What is NOT allowed behind the disclosure is anything a reader
   * could be misled by in its absence, so the compact line still refuses to
   * state a proportion, still says when the population is unstated, and still
   * says when a count could not be read. Only the explanations fold away.
   */
  compact?: boolean
}) {
  const ledger = useReviewLedger(caseId)

  // A denominator is printed only when the caller supplied one AND named the
  // population it counts. A bare "1,204 of 4,000,000" invites the reader to
  // decide for themselves what the 4,000,000 are.
  const stated = population?.count != null ? population : null

  const reviewed = formatCount(ledger.counts.reviewed)
  const opened = formatCount(ledger.counts.opened)
  // `null` is not zero. A roll-up that could not be read renders as an em-dash
  // and says why, because "0 reviewed" is a statement about the case and this
  // would be a statement about the network.
  const countsUnread =
    ledger.counts.reviewed == null || ledger.counts.opened == null

  // The responses that are unread RIGHT NOW, which is both what a re-read
  // would ask for and what the panel must name rather than leaving the reader
  // to assume the whole ledger is either fine or gone.
  const unread = ledger.parts.filter((part) => part.error != null)
  // A re-read that covered fewer than all four leaves this panel holding a
  // mixture of one fresh figure and three older ones, and a mixture presented
  // as one reading is the failure narrowing would otherwise have bought.
  const narrowed =
    ledger.retryScope != null &&
    ledger.retryScope.length < ledger.parts.length

  const qualifications = (
    <>
      <p className="rvw-note">
        “Opened” records that a screen showing the record was displayed.
        “Reviewed” records that an examiner said they had finished with it.
        Opening is not examining, and the two counts are never added together:
        every reviewed record is also an opened one. Both count distinct
        records, so two examiners opening the same record is one record.
      </p>
      {!stated && (
        <p className="rvw-note">
          Population not stated: nothing on this screen knows a population these
          counts belong to, so they are absolute figures and not a proportion of
          anything.
        </p>
      )}
      {stated != null &&
        ledger.population != null &&
        stated.count === ledger.population.total &&
        ledger.population.includesNonReviewableRows && (
          <p className="rvw-note">
            The denominator counts {ledger.population.label}, including
            containers, filesystems and partitions that nobody opens
            individually. Coverage read off it is a floor, not a measure.
          </p>
        )}
      <p className="rvw-note">{LEDGER_SCOPE_NOTE}</p>
    </>
  )

  const alerts = (
    <>
      {ledger.unrecorded > 0 && (
        <p className="rvw-note" role="status">
          {formatCount(ledger.unrecorded)}{' '}
          {ledger.unrecorded === 1 ? 'mark is' : 'marks are'} still being
          recorded and {ledger.unrecorded === 1 ? 'is' : 'are'} not counted
          above.
        </p>
      )}
      {ledger.idsCapped && (
        <p className="error-note" role="alert">
          This case holds more marks than one listing returns, so the rows on
          screen were matched against the listing’s ceiling only. A row shown as
          “not known” was past that ceiling — it is not a row nobody has opened.
        </p>
      )}
      {ledger.loadError && (
        <p className="error-note" role="alert">
          {ledger.loadError}
        </p>
      )}
      {ledger.retryFailedAt != null && unread.length > 0 && (
        // Said as its own event, with its own time. Without this the panel
        // answers an examiner's action by restoring the sentence it was
        // already showing, which is indistinguishable from a button that does
        // nothing — and leaves them unable to say when they tried. It names
        // what is STILL unread rather than repeating "the ledger": after a
        // narrowed re-read those are not the same list.
        <p className="error-note" role="alert">
          The re-read you asked for at{' '}
          {formatEpochSeconds(ledger.retryFailedAt)} did not succeed either.{' '}
          {formatCount(ledger.retriesFailed)}{' '}
          {ledger.retriesFailed === 1 ? 'attempt has' : 'attempts have'} now
          failed. Still unread: {listNames(unread.map((p) => p.label))}. Nothing
          drawn from {unread.length === 1 ? 'it' : 'those'} below is a record of
          what has been examined.
        </p>
      )}
      {/* Only when the LAST re-read they asked for is the one that succeeded.
          `retryFailedAt` is cleared as each attempt starts, so a null here is
          the current answer rather than a stale success sitting above a later
          failure. */}
      {ledger.retriedAt != null &&
        ledger.retryFailedAt == null &&
        ledger.loadError == null && (
        <p className="rvw-note" role="status">
          Re-read at {formatEpochSeconds(ledger.retriedAt)}, because you asked.{' '}
          {narrowed
            ? `Re-read: ${listNames(ledger.retryScope ?? [])}. The rest came back when the ledger was first read and was not asked for again, so what is on this screen is not all from one moment — the times below say when each part of it was read.`
            : 'What is shown here is what the server answered then.'}
        </p>
      )}
      <LedgerReadings
        parts={ledger.parts}
        narrowed={narrowed}
        retrying={ledger.retrying}
      />
      {unread.length > 0 && (
        <p className="rvw-retry">
          <button
            type="button"
            className="rvw-retry-button"
            onClick={() => void ledger.retryLoad()}
            aria-busy={ledger.retrying || undefined}
            aria-label={
              ledger.retrying
                ? 'Re-reading this case’s review ledger'
                : 'Read this case’s review ledger again'
            }
            title="Nothing re-reads the ledger on its own. A read that quietly succeeded after this panel had said it could not be read would leave two different answers on this screen with no moment you could name as the one that changed. Only the responses that are unread are asked for again: re-fetching a listing that came back would cost you a wait for figures nobody doubted."
          >
            {ledger.retrying ? 'Re-reading…' : 'Read the ledger again'}
          </button>{' '}
          <span className="rvw-note">
            The ledger is not re-read on its own, so what you see here does not
            change until you ask it to. Asking re-reads{' '}
            {unread.length === LEDGER_PARTS.length
              ? 'the whole ledger'
              : listNames(unread.map((p) => p.label))}
            .
          </span>
        </p>
      )}
      {ledger.writeError && (
        <p className="error-note" role="alert">
          {ledger.writeError}
        </p>
      )}
    </>
  )

  const breakdown = (
    <ExaminerBreakdown
      examiners={ledger.examiners}
      attempted={ledger.loaded}
      // A re-read in flight is its own state, and it is the "reading" one: the
      // panel must not answer with the ledger it could not read, nor with the
      // empty one it may turn out to be, while it is still finding out.
      rereading={ledger.retrying}
      // `counts.opened` is null exactly when the roll-up did not come back, so
      // it is the same fact the two figures above are drawn from rather than a
      // second, separately-derivable one that could drift out of step with it.
      read={ledger.counts.opened != null}
    />
  )

  if (compact) {
    return (
      <section
        className="rvw-panel rvw-compact"
        role="region"
        aria-label="Review ledger"
      >
        <span className="rvw-line">
          <strong>Review ledger (this case):</strong>{' '}
          {stated
            ? `${reviewed} of ${formatCount(stated.count)} ${stated.noun}`
            : reviewed}{' '}
          marked reviewed, {opened} opened at least once
          {stated ? '' : '; population not stated'}
          {countsUnread ? '; some counts could not be read' : ''}.
        </span>{' '}
        <details className="rvw-details">
          <summary>What these counts do and do not say</summary>
          {qualifications}
          {breakdown}
        </details>
        {alerts}
      </section>
    )
  }

  return (
    <section className="rvw-panel" role="region" aria-label="Review ledger">
      <h2>Review ledger</h2>
      <div className="rvw-figures">
        <div className="rvw-figure">
          <span className="rvw-figure-value">
            {stated ? `${reviewed} of ${formatCount(stated.count)}` : reviewed}
          </span>
          <span className="rvw-figure-label">
            marked reviewed{stated ? ` — ${stated.noun}` : ''}
          </span>
        </div>
        <div className="rvw-figure">
          <span className="rvw-figure-value">{opened}</span>
          <span className="rvw-figure-label">opened at least once</span>
        </div>
      </div>
      {qualifications}
      {breakdown}
      {alerts}
    </section>
  )
}

/**
 * When each part of this ledger was last read, and which part was not.
 *
 * ## Why it is not always on screen
 *
 * The ledger is four responses and in ordinary use they are never quite
 * contemporaneous — the roll-up is re-read after every mark while the id
 * listings are not. Printing four timestamps over every screen that carries a
 * coverage figure would be noise an examiner with forty-five minutes learns to
 * skip, and a disclosure that is always there is a disclosure nobody reads.
 *
 * ## Why it is not behind the compact panel's disclosure
 *
 * It appears in exactly the two cases where its absence could mislead, and in
 * those cases it is in the always-visible region even on the compact line:
 *
 *  - PART OF THE LEDGER IS UNREAD. Which part decides which figures on screen
 *    mean anything, and "the ledger could not be read" over a panel that is
 *    still showing real counts is as wrong as saying nothing.
 *  - THE LAST RE-READ WAS NARROWED. The examiner pressed a button, watched the
 *    error clear, and would otherwise reasonably take the whole panel to be as
 *    of that moment. Three of these figures are not.
 *
 * Times are absolute UTC rather than "read 3 hours ago" on purpose: a relative
 * age has to be recomputed to stay true, which means the screen changes with
 * nothing behind it, and it cannot be quoted in a report at all.
 */
function LedgerReadings({
  parts,
  narrowed,
  retrying,
}: {
  parts: LedgerPartStatus[]
  /** The last re-read the examiner asked for covered fewer than all four. */
  narrowed: boolean
  /** A re-read is running: it will say what it found when it lands. */
  retrying: boolean
}) {
  const unread = parts.filter((part) => part.error != null)
  if (retrying || (unread.length === 0 && !narrowed)) return null

  return (
    <div className="rvw-readings" role="status">
      <p className="rvw-note">
        This ledger is four separate readings and they are not all from the same
        moment. What is on this screen came from these:
      </p>
      <ul className="rvw-readings-list">
        {parts.map((part) => (
          <li key={part.part}>
            <span className="rvw-readings-part">{part.label}</span>
            {' — '}
            {part.error != null ? (
              <>
                not read; the attempt at {formatEpochSeconds(part.failedAt)} did
                not complete ({part.error}).{' '}
                {part.readAt != null
                  ? `What is shown from it is still the reading of ${formatEpochSeconds(
                      part.readAt,
                    )}.`
                  : 'Nothing on this screen is drawn from it, and nothing here is a claim that it is empty.'}
              </>
            ) : part.readAt != null ? (
              <>read at {formatEpochSeconds(part.readAt)}.</>
            ) : (
              <>
                not read. Nothing on this screen is drawn from it, and nothing
                here is a claim that it is empty.
              </>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}

/**
 * Who did what, per examiner.
 *
 * This is the handover: examiner B inherits the case and asks what A actually
 * looked at. The per-examiner columns are NOT the case figures broken down —
 * two examiners who both opened one record are two rows here and one record
 * there — so the caption says so rather than leaving a reader to sum them.
 */
function ExaminerBreakdown({
  examiners,
  attempted,
  read,
  rereading,
}: {
  examiners: ReviewExaminer[]
  /** The roll-up has been asked for. */
  attempted: boolean
  /** The roll-up came back. False after a read that failed. */
  read: boolean
  /** A re-read the examiner asked for is in flight. */
  rereading: boolean
}) {
  if (rereading) {
    return (
      <p className="rvw-note" role="status">
        Re-reading the case’s review ledger…
      </p>
    )
  }
  if (!attempted) {
    return <p className="rvw-note">Reading the case’s review ledger…</p>
  }
  if (!read) {
    // A read that failed is not an empty ledger. Saying "no examiner has
    // opened anything" here would be a claim about every examiner on the case,
    // made out of a claim about one request — and it would sit directly above
    // the alert saying the ledger could not be read, contradicting it.
    return (
      <p className="rvw-note">
        Who has examined what could not be read, so nothing here says which
        examiners have worked this case or what they opened.
      </p>
    )
  }
  if (examiners.length === 0) {
    // "Nobody has marked anything" is a real answer now that the ledger is the
    // case's rather than this browser's, and it is stated as one — but only
    // once the roll-up has actually been read.
    return (
      <p className="rvw-note">
        No examiner has opened or reviewed anything in this case.
      </p>
    )
  }
  return (
    <table className="rvw-examiners">
      <caption>
        Marks by examiner. Each column counts one examiner’s own marks; they do
        not add up to the case figures, because two examiners may have opened
        the same record.
      </caption>
      <thead>
        <tr>
          <th scope="col">Examiner</th>
          <th scope="col">Opened</th>
          <th scope="col">Reviewed</th>
          <th scope="col">First opened</th>
          <th scope="col">Last activity</th>
        </tr>
      </thead>
      <tbody>
        {examiners.map((e) => (
          <tr key={e.examiner}>
            <th scope="row">{e.examiner}</th>
            <td className="mono">{formatCount(e.opened)}</td>
            <td className="mono">{formatCount(e.reviewed)}</td>
            <td className="mono">{formatEpochSeconds(e.firstOpenedAt)}</td>
            <td className="mono">{formatEpochSeconds(e.lastActivityAt)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/**
 * The ledger reports times in epoch SECONDS, matching `artifact_bookmarks`.
 * Every other time on screen is rendered from an ISO string in UTC and these
 * are not allowed to be the exception — an examiner comparing a review time
 * against a message time must be comparing like with like.
 */
function formatEpochSeconds(seconds: number | null): string {
  // Null reaches here from times that may not exist — the moment a reading
  // failed, when none has. It renders as the em-dash every other missing figure
  // in this codebase uses, never as an epoch date in 1970.
  if (seconds == null || !Number.isFinite(seconds)) return '—'
  return formatUtc(new Date(seconds * 1000).toISOString())
}
