import { createContext, useContext, useEffect } from 'react'
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { BookmarkControl } from '../../components/bookmark/BookmarkControl'
import { BookmarksProvider } from '../../components/bookmark/BookmarksProvider'
import {
  ReviewLedgerPanel,
  ReviewMark,
} from '../../components/bookmark/ReviewMark'
import { useReviewLedgerWriter } from '../../hooks/useReviewed'
import { formatCount, formatDecimal, formatUtc } from '../../lib/format'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import {
  getCommsHistogram,
  getCommsRanking,
  type CommsHistogram,
  type CommsRanking,
} from '../analysis/api'
import { BUCKET_TARGET, TOP_N } from '../analysis/RichCharts'
import {
  makeCorrelationPage,
  type CorrelationHistogram,
  type CorrelationRanking,
  type CorrelationRankingState,
} from '../correlation/CorrelationPage'
import {
  CHANNEL_OF,
  COMMS_TYPES,
  normalizeComms,
  type CommChannel,
  type CommContent,
  type CommEvent,
} from './normalize'
import './comms.css'

/** Heading of the frequency bar list, in both of its labelled variants. */
const TOP_TITLE = 'Most-contacted'

/** Heading of the volume chart, in both of its labelled variants. */
const HISTO_TITLE = 'Volume over time'

/**
 * How long the search box must be still before the aggregation is asked again.
 * The endpoint groups over every communication record in the case, so firing it
 * per keystroke asks the database to count ninety thousand rows a dozen times
 * to answer one question.
 */
const RANKING_DEBOUNCE_MS = 200

/**
 * The ParsedRecord type behind each channel label, derived from `CHANNEL_OF`.
 *
 * The channel tiles are labelled "SMS" and "Telegram"; the ranking endpoint is
 * parameterised by "AndroidSms" and "TelegramMessage". Sending the tile label
 * would be answered as "no such channel" — an empty league table presented as a
 * finding about the case — so the tile filter is translated here first.
 *
 * A channel that more than one record type feeds maps to null. The endpoint
 * takes a single type, so such a channel is simply not a question it can be
 * asked, and the page falls back rather than send one of the two and label the
 * answer as the whole channel.
 */
const TYPE_OF_CHANNEL = new Map<string, string | null>()
for (const [type, channel] of Object.entries(CHANNEL_OF)) {
  TYPE_OF_CHANNEL.set(channel, TYPE_OF_CHANNEL.has(channel) ? null : type)
}

/**
 * Hold `value` until it has stopped changing for `ms`, forgetting it the moment
 * the case changes.
 *
 * The held needle is scoped to the case for the same reason the filter boxes
 * that feed it are (BUG-282, B2-145): this page stays mounted across a
 * `:caseId` route change. In a plain `useState` the needle typed under case A
 * survives into the first render under case B — where the search box has
 * already reset to '' — and the aggregation below is keyed on the held value,
 * so the page asks case B for case A's needle. The endpoint audits every call,
 * which makes that request an entry in case B's custody trail for a
 * counterparty search the examiner never performed. Resolving the held value
 * during render, rather than clearing it in an effect, means the stale needle
 * is never observable and so can never be sent.
 */
function useDebouncedNeedle(caseId: string, value: string, ms: number): string {
  const [held, setHeld] = useEntityScopedState(caseId, '')
  useEffect(() => {
    if (held === value) return
    const timer = setTimeout(() => setHeld(value), ms)
    return () => clearTimeout(timer)
  }, [value, ms, held, setHeld])
  return held
}

/**
 * "WhatsApp 78,221; iMessage 15,041" — the server's per-type breakdown in the
 * vocabulary of the tiles. A type this page does not correlate keeps its raw
 * name and is marked as such: it would otherwise sit in the list looking like
 * one of the channels on screen while contributing records to a ranking the
 * rest of the page cannot show.
 */
function describeByType(byType: [string, number][]): string {
  return byType
    .map(([type, count]) => {
      const label = CHANNEL_OF[type]
      return label
        ? `${label} ${formatCount(count)}`
        : `${type} ${formatCount(count)}, which this page does not display`
    })
    .join('; ')
}

/**
 * What the exact ranking covers, in the server's own numbers.
 *
 * Three different populations meet in this paragraph and the whole point of it
 * is that they stay apart: the correspondents (narrowed by the search needle),
 * the record counts (narrowed by the channel tile alone), and the exclusions
 * (likewise about the case). An examiner who reads "93,338" as the size of
 * their search result has been misled by the layout even if every number is
 * right.
 */
function exactNote(
  data: CommsRanking,
  scope: string,
  needle: string,
  shown: number,
): ReactNode {
  const sentences: string[] = []

  const breakdown = data.by_type ? ` (${describeByType(data.by_type)})` : ''
  sentences.push(
    data.total_records != null
      ? `Counted by the server over all ${formatCount(data.total_records)} ${scope}s in this case${breakdown} — not over the slice this page loaded.`
      : `Counted by the server over the ${scope}s in this case${breakdown} — not over the slice this page loaded.`,
  )

  // The rule stated exactly, because it is wrong in both directions otherwise.
  // The server folds case for ASCII letters only — SQLite's `lower()` cannot
  // fold anything else — so "SAHIN" does find "Sahin", and saying "as typed"
  // would understate the population in the ordinary case. But "ünal" does not
  // find "Ünal", where this page's own fallback filter (JavaScript's
  // Unicode-aware `toLowerCase()`) would, so an unqualified "contains" would
  // overstate it. Naming the rule covers both, and matches the wording on the
  // server's own doc comment so the two describe one thing.
  const matching = needle
    ? ` whose identifier contains “${needle}” (case-insensitive for A–Z)`
    : ''
  if (data.distinct_contacts != null) {
    sentences.push(
      `Showing the top ${shown} of ${formatCount(data.distinct_contacts)} correspondents${matching}.`,
    )
  } else if (data.has_more === true) {
    sentences.push(
      `Showing the top ${shown} correspondents${matching}; more match than are shown, and the server did not state how many.`,
    )
  } else if (data.has_more === false) {
    sentences.push(`Showing all ${shown} correspondents${matching}.`)
  } else {
    sentences.push(
      `Showing ${shown} correspondents${matching}; the server did not state how many there are in all.`,
    )
  }

  sentences.push(
    'Those record counts describe the case, narrowed by the channel tile alone; they are not narrowed by the filter box.',
  )

  // The two "no counterparty" numbers are different facts about different rows
  // and are never summed: one is records carrying none of the counterparty
  // keys, the other is calls the device itself logged without a number, which
  // the parser records as the literal string "Unknown". Seating an "Unknown" at
  // the top of a league table would be the worst outcome available here, so the
  // server drops them — which is exactly why their count has to be said aloud.
  const excluded: string[] = []
  if (data.summary_records) {
    excluded.push(`${formatCount(data.summary_records)} summary rows`)
  }
  if (data.unrankable_records) {
    excluded.push(
      `${formatCount(data.unrankable_records)} records that carried no counterparty field at all`,
    )
  }
  if (data.records_without_counterparty) {
    excluded.push(
      `${formatCount(data.records_without_counterparty)} calls the device recorded with no number`,
    )
  }
  if (excluded.length > 0) {
    sentences.push(
      `Excluded from the ranking: ${excluded.join('; ')}.` +
        (excluded.length > 1
          ? ' Those are separate populations and do not add up to one figure.'
          : ''),
    )
  } else if (
    data.summary_records === 0 &&
    data.unrankable_records === 0 &&
    data.records_without_counterparty === 0
  ) {
    sentences.push('The server excluded nothing from this ranking.')
  }

  return sentences.join(' ')
}

/**
 * Rank the correspondents server-side wherever that is a correct answer to what
 * the page is currently asking, and say plainly when it is not.
 *
 * The endpoint takes a channel and a needle, which are two of this page's three
 * cross-filters, and `matches` here is a case-insensitive substring test on the
 * counterparty — the same predicate the needle means server-side. The third
 * filter, the contact bar, narrows the view to a single correspondent; ranking
 * the correspondents of a one-correspondent view is not a question, and it is
 * not one this endpoint takes, so that state falls back to the browser's own
 * count over the loaded slice and is labelled as such.
 */
function useCommsRanking({
  caseId,
  primary,
  secondary,
  search,
}: CorrelationRankingState<CommChannel>): CorrelationRanking {
  const needle = search.trim()
  const debounced = useDebouncedNeedle(caseId, needle, RANKING_DEBOUNCE_MS)

  const channelType =
    primary == null ? null : (TYPE_OF_CHANNEL.get(primary) ?? null)
  const askable = primary == null || channelType != null

  const query = useQuery({
    // "No channel selected" and "a channel selected that cannot be asked
    // about" are two different questions and must not share a cache entry.
    // `enabled: false` suppresses the fetch but not the read: React Query still
    // hands back whatever is cached under the key, so collapsing both states
    // onto '' would answer the unaskable tile with the WHOLE-CASE ranking,
    // labelled exact and headed by the tile's own name, and the sentence
    // explaining why no server-side ranking exists for that tile would never
    // render at all.
    queryKey: [
      'comms-ranking',
      caseId,
      askable ? (channelType ?? '') : `unaskable:${primary}`,
      debounced,
    ],
    queryFn: () =>
      getCommsRanking(caseId, {
        channel: channelType ?? undefined,
        q: debounced || undefined,
        limit: TOP_N,
      }),
    enabled: askable,
    staleTime: Infinity,
    // One failure falls back to the labelled slice ranking immediately rather
    // than leaving the bars unlabelled for three retries.
    retry: false,
  })

  // The query is keyed on the DEBOUNCED needle, so between a keystroke and the
  // request that follows it `query.data` answers a question the examiner has
  // already changed. Presenting it under the word "exact" would put one
  // needle's ranking behind another needle's label.
  //
  // A failed reload is the same defect in different clothes, and the guard has
  // to be the same. React Query keeps the last successful payload when a
  // refetch errors, and an ingest finishing invalidates every query keyed by
  // this case — the ranking among them. Without the `isError` term, a refetch
  // that then failed would leave the PREVIOUS answer on screen under "exact,
  // counted server-side", its case-wide totals asserted in the present tense
  // beside a record table that has already repainted with the new records. An
  // answer whose reload failed is not an exact answer to what is on screen now,
  // so it is dropped and the labelled slice ranking says why instead.
  //
  // `askable` is repeated here rather than left to the key alone: a ranking
  // this page did not ask for must never be presentable, whatever a future
  // cache key happens to collide with.
  const data =
    askable && debounced === needle && !query.isError
      ? (query.data ?? null)
      : null

  const scope = primary ? `${primary} record` : 'communication record'

  if (data != null && secondary == null) {
    const items = data.contacts.map((c) => ({ label: c.contact, count: c.count }))
    return {
      items,
      title: `${TOP_TITLE} (exact, counted server-side)`,
      note: exactNote(data, scope, needle, items.length),
    }
  }

  // Everything below draws the browser's own count over the loaded slice, so
  // every branch has to leave the examiner in no doubt that that is what they
  // are reading.
  let reason: string
  if (query.isError) {
    reason = `The exact server-side ranking could not be loaded (${query.error?.message ?? 'no reason given'}).`
  } else if (!askable) {
    reason = `No server-side ranking can be asked for the ${primary} tile: more than one record type feeds it.`
  } else if (secondary != null) {
    reason =
      'A ranking of correspondents is not a question that can be asked of a single-correspondent view.'
  } else {
    reason = 'Counting the exact ranking server-side…'
  }

  // The count the server does know for the selected contact, when the answer it
  // has already given happens to contain it. Stating it beside a slice count of
  // 1 is the difference between "this contact is barely here" and "this page
  // has loaded one of their 900 records".
  const selectedCount =
    secondary != null
      ? (data?.contacts.find((c) => c.contact === secondary)?.count ?? null)
      : null

  return {
    items: null,
    title: `${TOP_TITLE} (within the loaded slice)`,
    note: (
      <>
        {reason} These bars rank only the slice of records this page loaded, so
        the ORDER can be wrong, not just the totals.
        {secondary != null && (
          <>
            {' '}
            Narrowed to “{secondary}”
            {selectedCount != null
              ? `, for which the server counted ${formatCount(selectedCount)} ${scope}s in this case`
              : ''}{' '}
            — clear the contact filter to see the exact ranking.
          </>
        )}
      </>
    ),
  }
}

/**
 * A bucket width in words.
 *
 * Never as a calendar unit unless it is exactly one: `FRIENDLY_BUCKET_SECONDS`
 * measures a "month" as 30.4375 days from the epoch, so calling that bucket "a
 * month" would have an examiner read a bar as covering March when its right
 * edge falls in April.
 */
function describeBucketSeconds(secs: number): string {
  const plural = (n: number, unit: string) =>
    `${formatCount(n)} ${unit}${n === 1 ? '' : 's'}`
  if (secs % 86400 === 0) return plural(secs / 86400, 'day')
  if (secs >= 86400) return `${formatDecimal(secs / 86400, 2)} days`
  if (secs % 3600 === 0) return plural(secs / 3600, 'hour')
  if (secs % 60 === 0) return plural(secs / 60, 'minute')
  return plural(secs, 'second')
}

/** "EmailMessage 289; CallLog 8" — the per-type shortfall in the server's names. */
function describeUnplaceableTypes(byType: [string, number][] | null): string {
  if (byType == null || byType.length === 0) return ''
  return ` (${byType.map(([t, n]) => `${t} ${formatCount(n)}`).join('; ')})`
}

/**
 * The records that matched and are not on the chart, by class, never summed.
 *
 * The census is ORDERED server-side precisely so each record lands in exactly
 * one of these, and adding them here would undo that: a call-log summary row
 * carries no time key either, so a total built from these four would count it
 * twice and produce a shortfall larger than the population it describes.
 */
function describeUnplaced(data: CommsHistogram): string | null {
  const parts: string[] = []
  if (data.unplaceable_absent) {
    parts.push(
      `${formatCount(data.unplaceable_absent)} records carried no time key at all`,
    )
  }
  if (data.unplaceable_value) {
    parts.push(
      `${formatCount(data.unplaceable_value)} records carried a value no reading of which is admissible${describeUnplaceableTypes(data.by_type_unplaceable)}`,
    )
  }
  if (data.not_a_message) {
    parts.push(
      `${formatCount(data.not_a_message)} rows are not messages at all — a summary row, or a parser status stub standing for a database that could not be read`,
    )
  }
  if (data.unreadable_metadata) {
    parts.push(
      `${formatCount(data.unreadable_metadata)} records carried metadata that does not parse`,
    )
  }
  if (parts.length === 0) return null
  return (
    `Not on the chart: ${parts.join('; ')}.` +
    (parts.length > 1
      ? ' Those are separate populations and do not add up to one figure.'
      : '')
  )
}

/**
 * What the exact chart covers, in the server's own numbers.
 *
 * Three populations meet here and the whole job of the paragraph is to keep
 * them apart, exactly as in `exactNote` above: the case (narrowed by the
 * channel tile alone), the records in scope for the chart (narrowed by the
 * channel, the filter box AND the contact bar), and the placed subset of those
 * that the bars actually draw. An examiner who reads the bars' total as the
 * size of the case, or the case total as the size of their search, has been
 * misled by the layout even though every number on it is right.
 */
function exactHistogramNote(
  data: CommsHistogram,
  scope: string,
  needle: string,
  contact: string | null,
): string {
  const sentences: string[] = []

  sentences.push(
    data.total_records != null
      ? `Counted by the server over all ${formatCount(data.total_records)} ${scope}s in this case — not over the slice this page loaded.`
      : `Counted by the server over the ${scope}s in this case — not over the slice this page loaded.`,
  )
  sentences.push(
    'That case total describes the case narrowed by the channel tile alone; it is not narrowed by the filter box or by the contact filter.',
  )

  // The needle's folding rule stated exactly, because an unqualified
  // "contains" is wrong in both directions. SQLite's `lower()` folds ASCII
  // letters only, so "SAHIN" does find "Sahin" but "ünal" does not find
  // "Ünal", where this page's own fallback filter would. See `exactNote`.
  const narrowing: string[] = []
  if (contact) narrowing.push(`the contact filter “${contact}”`)
  if (needle) {
    narrowing.push(
      `a counterparty containing “${needle}” (case-insensitive for A–Z)`,
    )
  }
  const by = narrowing.length > 0 ? ` under ${narrowing.join(' and ')}` : ''
  sentences.push(
    data.matched_records != null
      ? `${formatCount(data.matched_records)} of them are in scope for this chart${by}.`
      : `The server did not state how many are in scope for this chart${by}.`,
  )

  const matched = data.matched_records ?? 0
  if (
    matched > 0 &&
    data.placed_as_written != null &&
    data.placed_by_rescue != null
  ) {
    sentences.push(
      data.placed_by_rescue > 0
        ? `${formatCount(data.placed_as_written)} of those were read as written and are drawn as such; a further ${formatCount(data.placed_by_rescue)} could be placed ONLY by assuming which unit the parser wrote, and are drawn as the faint part of their bar and named in its tooltip. An instant reached that way is a weaker fact than one read to contract.`
        : `${formatCount(data.placed_as_written)} of those were placed by reading the value as written; not one of them rests on an assumption about which unit the parser wrote.`,
    )
  }

  if (matched > 0) {
    const unplaced = describeUnplaced(data)
    if (unplaced) sentences.push(unplaced)
  }

  if (data.bucket_seconds != null && data.buckets.length > 0) {
    sentences.push(
      `Each bar covers ${describeBucketSeconds(data.bucket_seconds)}, measured in whole multiples of that width from the Unix epoch — the buckets are not aligned to calendar days or months, so a bar's edges fall where that arithmetic puts them.`,
    )
  }

  if (data.buckets.length > 0) {
    sentences.push(
      'These bars are counted over the case; the table of individual records below lists only the slice this page loaded, so a tall bar here can stand above a table showing no rows for it. That is the table being short, not the bar being wrong.',
    )
  }

  return sentences.join(' ')
}

/**
 * Which of the empty states this is, said in words.
 *
 * `buckets: []` cannot tell them apart on its own, which is why the endpoint
 * carries the whole census on the empty-extent path. Four findings arrive
 * looking identical, and three of them are answers about the evidence that an
 * examiner would otherwise have to guess between: a case with no
 * communications in it, a case full of them that the parsers recorded no times
 * for, and a filter that simply matched nothing. (The fourth — the request
 * failed — never reaches here, because a failure falls back to the client
 * chart and says so there.)
 */
function emptyHistogramNote(data: CommsHistogram, scope: string): string {
  const placed =
    data.placed_as_written != null && data.placed_by_rescue != null
      ? data.placed_as_written + data.placed_by_rescue
      : null

  if (data.total_records === 0) {
    return `This case holds no ${scope}s at all, so there is nothing to draw. That is a statement about what the evidence in this case contains, not about the filters on this screen.`
  }
  if (data.matched_records === 0) {
    const of =
      data.total_records != null
        ? ` out of ${formatCount(data.total_records)} in the case`
        : ''
    return `The filters on this screen matched none of the ${scope}s${of}. That is a statement about the filters, not about the case.`
  }
  if (placed === 0 && data.matched_records != null && data.matched_records > 0) {
    return `${formatCount(data.matched_records)} ${scope}s matched the filters on this screen and not one of them could be placed in time. That is not a statement that nothing happened in this period — it is a statement that these records do not say when, and the breakdown below says in what way.`
  }
  return 'The server drew no bars and stated no census that explains why, so this chart cannot say whether nothing happened, nothing matched, or nothing could be placed.'
}

/**
 * Bucket the volume chart server-side wherever that is a correct answer to what
 * the page is currently asking, and say plainly when it is not.
 *
 * Unlike the ranking beside it, this endpoint takes all three of the page's
 * cross-filters — a chart of one correspondent's traffic over time is a
 * perfectly good question — so the only state it cannot answer is a channel
 * tile fed by more than one record type, which it has no parameter for.
 */
function useCommsHistogram({
  caseId,
  primary,
  secondary,
  search,
}: CorrelationRankingState<CommChannel>): CorrelationHistogram {
  const needle = search.trim()
  const debounced = useDebouncedNeedle(caseId, needle, RANKING_DEBOUNCE_MS)

  const channelType =
    primary == null ? null : (TYPE_OF_CHANNEL.get(primary) ?? null)
  const askable = primary == null || channelType != null

  const query = useQuery({
    // "No channel selected" and "a channel selected that cannot be asked
    // about" are two different questions and must not share a cache entry —
    // see `useCommsRanking` for what collapsing them does.
    queryKey: [
      'comms-histogram',
      caseId,
      askable ? (channelType ?? '') : `unaskable:${primary}`,
      debounced,
      secondary ?? '',
    ],
    queryFn: () =>
      getCommsHistogram(caseId, {
        channel: channelType ?? undefined,
        q: debounced || undefined,
        contact: secondary ?? undefined,
        buckets: BUCKET_TARGET,
      }),
    enabled: askable,
    staleTime: Infinity,
    retry: false,
  })

  // Held to the same three conditions as the ranking, for the same three
  // reasons: a chart drawn for a needle the examiner has already changed, a
  // chart whose reload failed but whose previous answer React Query still
  // holds, and a chart for a question this page did not ask.
  const data =
    askable && debounced === needle && !query.isError
      ? (query.data ?? null)
      : null

  const scope = primary ? `${primary} record` : 'communication record'

  if (data != null) {
    return {
      // Seconds on the wire, milliseconds on the chart. The unit is in the
      // field name because a 1000x mix renders 2024 as 1970-01-20 — a wrong
      // answer that looks like a right one.
      buckets: data.buckets.map((b) => ({
        startMs: b.bucket_start_secs * 1000,
        count: b.count,
        rescued: b.rescued_count,
      })),
      bucketMs:
        data.bucket_seconds != null ? data.bucket_seconds * 1000 : null,
      title: `${HISTO_TITLE} (exact, counted server-side)`,
      note: exactHistogramNote(data, scope, needle, secondary),
      emptyNote: emptyHistogramNote(data, scope),
    }
  }

  let reason: string
  if (query.isError) {
    reason = `The exact server-side histogram could not be loaded (${query.error?.message ?? 'no reason given'}).`
  } else if (!askable) {
    reason = `No server-side histogram can be asked for the ${primary} tile: more than one record type feeds it.`
  } else {
    reason = 'Counting the exact histogram server-side…'
  }

  return {
    buckets: null,
    bucketMs: null,
    title: `${HISTO_TITLE} (within the loaded slice)`,
    note: `${reason} These bars are bucketed in the browser from the slice of records this page loaded, so both their heights and the extent of the axis under them describe that slice and not the case.`,
  }
}

/**
 * The case the row cells belong to.
 *
 * `makeCorrelationPage` renders cells through a plain `renderCells(event)`
 * function that is given no case, and this page is mounted both at
 * `/cases/:caseId/communications` and, with an explicit prop, inside the
 * workbench — so a cell cannot recover the case from the router alone in the
 * unit tests that mount it without that route. The exported wrapper below
 * resolves the case exactly as the correlation shell does and publishes it
 * here, which keeps the two from ever disagreeing.
 */
const CommsCaseContext = createContext<string | null>(null)

/** A call's duration in the same m:ss shape the call-log viewer uses. */
function formatCallDuration(secs: number | null): string | null {
  if (secs == null || secs < 0) return null
  const minutes = Math.floor(secs / 60)
  const seconds = secs % 60
  return `${minutes}:${String(seconds).padStart(2, '0')}`
}

/**
 * What the row shows in its message cell.
 *
 * Never a serialised record and never an empty cell. Where the record carries
 * no renderable field, the cell says what the record IS — a call of a stated
 * length, an email with no subject, a message whose only text was an attachment
 * placeholder — because "this row has nothing to show" and "this row was not
 * looked at properly" must not look alike in a screenshot taken into court.
 */
function ContentCell({ content }: { content: CommContent }) {
  if (content.kind === 'call') {
    const duration = formatCallDuration(content.durationSeconds)
    return (
      <span className="cm-content">
        {duration
          ? `Call, ${duration}`
          : 'Call; the record states no duration'}
      </span>
    )
  }
  if (content.kind === 'subject') {
    return (
      <span className="cm-content" title={content.text}>
        {content.text}
      </span>
    )
  }
  if (content.kind === 'text') {
    return (
      // The full text is the title so a long message can be read without
      // leaving the table, while the cell itself stays one row high.
      <span className="cm-content" title={content.text}>
        {content.text}
      </span>
    )
  }
  return (
    <span className="cm-content muted" title={content.because}>
      {content.because}
    </span>
  )
}

/**
 * The hop this page existed without: message → the conversation it sits in.
 *
 * `MessagingViewer` has supported `?conv=` and `?focus=` deep links all along;
 * nothing pointed at them from here, so clicking a row landed on the record
 * artifact, whose only tab is that record's raw JSON. The examiner had to climb
 * the breadcrumb to the chat database, open its Conversation tab, find the
 * thread again and scroll to the date by hand.
 *
 * A call gets no link, and the cell says why rather than going blank: there is
 * no thread view for one, so the record page IS the right destination. A
 * message whose thread key could not be addressed is treated the same way —
 * see `threadKeyOf` for why guessing would be worse than declining. An email
 * with no `Message-ID`, `In-Reply-To` or `References` header falls in that
 * second class and gets its own sentence, because the reason is specific and
 * an examiner can check it against the record (§5.14).
 */
function ConversationCell({ event }: { event: CommEvent }) {
  const caseId = useContext(CommsCaseContext)
  // This cell writes to the review ledger and never reads it, so it takes the
  // writer rather than the ledger. Subscribing here put a second listener on
  // every one of the table's five hundred rows, each of which re-rendered
  // whenever any other row was marked.
  const ledger = useReviewLedgerWriter(caseId ?? '')

  if (caseId == null) return <span className="muted">—</span>
  if (event.threadKey == null) {
    return (
      <span
        className="muted"
        title={
          event.channel === 'Call'
            ? 'A call has no conversation view; the record itself is the whole of what was recovered.'
            : event.channel === 'Email'
              ? 'This message carries no Message-ID, In-Reply-To or References header, so the exchange it belongs to cannot be addressed from the evidence. The record itself is the whole of what was recovered.'
              : 'This record’s conversation cannot be addressed, so no link is offered rather than one that could open a different thread.'
        }
      >
        no conversation view
      </span>
    )
  }

  // The record type's canonical address, carrying the selection the old form
  // carried. `workbench?type=` redirects onto exactly this, so emitting it
  // would only add a hop and leave the superseded address in the URL bar —
  // which is the one an examiner copies into a note.
  const to =
    `/cases/${caseId}/analysis/${encodeURIComponent(event.recordType)}` +
    `?conv=${encodeURIComponent(event.threadKey)}` +
    `&focus=${encodeURIComponent(event.artifactId)}`

  return (
    <Link
      to={to}
      aria-label={`Open the conversation containing ${rowSubject(event)}`}
      // Following this link is one of the few acts on this page that genuinely
      // puts the record in front of the examiner, so it is the one that records
      // an opening. Scrolling a row into view is not, and does not.
      onClick={() => ledger.markOpened(event.artifactId)}
    >
      conversation
    </Link>
  )
}

/**
 * How a row names itself in the accessible label of its controls.
 *
 * The noun comes from what the record IS rather than from the channel tile, and
 * the channel's own name is deliberately left out: a screen reader announcing
 * "bookmark the iMessage message with…" reads worse, and a label carrying the
 * tile's exact wording makes every row indistinguishable from the tile in any
 * by-name lookup.
 */
function rowSubject(event: CommEvent): string {
  const noun =
    event.content.kind === 'call'
      ? 'call'
      : event.content.kind === 'subject'
        ? 'email'
        : 'message'
  const when =
    event.time != null
      ? ` at ${formatUtc(new Date(event.time).toISOString())}`
      : ' (undated)'
  return `the ${noun} with ${event.contact}${when}`
}

/** The capture control for one row. */
function MarkCells({ event }: { event: CommEvent }) {
  const caseId = useContext(CommsCaseContext)
  if (caseId == null) return null
  return (
    <BookmarkControl
      caseId={caseId}
      artifactId={event.artifactId}
      subject={rowSubject(event)}
    />
  )
}

function ReviewCell({ event }: { event: CommEvent }) {
  const caseId = useContext(CommsCaseContext)
  if (caseId == null) return null
  return (
    <ReviewMark
      caseId={caseId}
      id={event.artifactId}
      subject={rowSubject(event)}
    />
  )
}

/**
 * Unified communications. Everything structural — the fan-out, the failure and
 * truncation guards, the incompleteness banner, the case-scoped cross-filters —
 * lives in `makeCorrelationPage`; this file is the vocabulary of the comms view
 * and nothing else.
 */
const CommsCorrelation = makeCorrelationPage<CommEvent, CommChannel>({
  title: 'Communications',
  intro:
    'Unified communications across iMessage, WhatsApp, SMS, calls, and email — volume over time and the most-contacted parties.',
  queryKey: 'comms',
  types: COMMS_TYPES,
  normalize: normalizeComms,
  loadingLabel: 'Correlating messages, calls, and email…',
  subjectNoun: 'communications',
  sourceNoun: 'communication types',
  recordNoun: 'communication records',
  correlationKeyNoun: 'a counterparty to correlate on',
  emptyTitle: 'No communications',
  emptyBody:
    'This case has no messaging, call-log, or email records to correlate.',
  searchPlaceholder: 'Filter by contact…',
  searchLabel: 'Filter communications',
  // One tile per channel actually present, in first-seen order. A channel with
  // no events gets no tile rather than a zero — the tiles are what the examiner
  // reads as "these are the channels in this case".
  stats: (events) => {
    const counts = new Map<string, number>()
    for (const e of events) counts.set(e.channel, (counts.get(e.channel) ?? 0) + 1)
    return [...counts.entries()].map(([key, count]) => ({
      key,
      label: key,
      count,
      tone: 'accent' as const,
    }))
  },
  primaryOf: (e) => e.channel,
  topTitle: TOP_TITLE,
  secondaryOf: (e) => e.contact,
  // The counterparty substring test the ranking endpoint's `q` means, which is
  // what lets the needle be pushed down to the server unchanged.
  matches: (e, needle) => e.contact.toLowerCase().includes(needle),
  useRanking: useCommsRanking,
  useHistogram: useCommsHistogram,
  timeOf: (e) => e.time,
  artifactIdOf: (e) => e.artifactId,
  rowKey: (e) => `${e.channel}-${e.artifactId}`,
  columns: [
    'Mark',
    'Contact',
    'Channel',
    'Direction',
    'Message',
    'Time (UTC)',
    'Conversation',
    'Review',
  ],
  renderCells: (e) => (
    <>
      <td>
        <MarkCells event={e} />
      </td>
      <td className="mono">{e.contact}</td>
      <td>
        <span className="badge">{e.channel}</span>
      </td>
      <td>{e.direction}</td>
      <td className="cm-content-cell">
        <ContentCell content={e.content} />
      </td>
      <td className="mono">
        {e.time != null ? formatUtc(new Date(e.time).toISOString()) : '—'}
      </td>
      <td>
        <ConversationCell event={e} />
      </td>
      <td>
        <ReviewCell event={e} />
      </td>
    </>
  ),
})

/**
 * Unified communications, with the case published to the row cells.
 *
 * The case is resolved here exactly as `makeCorrelationPage` resolves it — prop
 * first, router second — so a cell and the shell around it can never be looking
 * at different cases.
 */
export function CommsPage({ caseId: caseIdProp }: { caseId?: string } = {}) {
  const params = useParams() as { caseId?: string }
  const caseId = caseIdProp ?? params.caseId ?? null

  return (
    <CommsCaseContext.Provider value={caseId}>
      {/* No population is offered to the panel, and that is deliberate — and
          it stays deliberate now that the ledger is on the server and the stats
          endpoint offers an exact case-wide total. The marks the panel counts
          are case-wide, made here, in the gallery, anywhere; this page has only
          ever loaded a capped slice of sixteen record types. A denominator
          printed here would be read against the page it is printed on, and
          those are two different populations. The panel says the population is
          not stated instead of borrowing one that does not fit. */}
      {caseId && <ReviewLedgerPanel caseId={caseId} compact />}
      {/* The case's bookmarks are looked up once for the whole table rather
          than once per row. Without this each of the capped five hundred rows
          opened its own pair of react-query observers on the same case-wide
          list, so one capture invalidated a thousand of them — see
          `BookmarksProvider`. */}
      {caseId ? (
        <BookmarksProvider caseId={caseId}>
          <CommsCorrelation caseId={caseId} />
        </BookmarksProvider>
      ) : (
        <CommsCorrelation />
      )}
    </CommsCaseContext.Provider>
  )
}
