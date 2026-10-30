import { useMemo } from 'react'
import type { ReactNode } from 'react'
import { useQueries } from '@tanstack/react-query'
import { useParams } from 'react-router-dom'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { IncompletenessBanner } from '../../components/Incompleteness'
import { summarizeIncompleteness } from '../../lib/incompleteness'
import { getAllRecords, type ParsedRecord } from '../analysis/api'
import { ArtifactLink } from '../analysis/cells'
import { formatCount } from '../../lib/format'
import {
  EventHistogram,
  StatTiles,
  TimeHistogram,
  TopBars,
  type HistoBucket,
  type StatTile,
  type TopItem,
} from '../analysis/RichCharts'
import '../analysis/analysis.css'

/** Rows rendered in the correlated table before the examiner must narrow. */
const TABLE_CAP = 500
/** Pages of each record type pulled per correlation view. */
const MAX_PAGES = 20

/**
 * A correlation page fans out over several ParsedRecord types, projects each
 * one down to a common event shape, and presents the union as charts plus a
 * table with two cross-filters.
 *
 * The shell is shared because every guard on it is a statement about the
 * evidence rather than about layout: which types failed, which hit the page
 * cap, which records declared themselves short, and whether an empty table
 * means "nothing happened" or "we could not read it". Communications and
 * execution were maintained as two copies of these guards and drifted at every
 * fix (BUG-282, B2-145/146 were each applied twice); a guard that lands in one
 * copy and not the other is a screen that quietly answers a different question.
 */
export interface CorrelationConfig<E, P extends string> {
  /** Page heading. */
  title: string
  /** Sentence under the heading describing what was correlated. */
  intro: string
  /** react-query key prefix; must be unique per correlation page. */
  queryKey: string
  /** ParsedRecord types fanned out over. */
  types: readonly string[]
  /** Project one type's records into unified events. */
  normalize: (type: string, records: ParsedRecord[]) => E[]
  /** Shown while the fan-out is in flight. */
  loadingLabel: string
  /** What failed, for the all-failed sentence ("communications"). */
  subjectNoun: string
  /** What the fanned-out types are called ("communication types"). */
  sourceNoun: string
  /** Noun for the incompleteness banner ("communication records"). */
  recordNoun: string
  /**
   * The field a record must carry to be placeable on this view ("a
   * counterparty to correlate on"). Named in the empty state when records were
   * loaded but none of them could be normalised, so "nothing here" and "we
   * loaded rows we could not place" never read alike.
   */
  correlationKeyNoun: string
  emptyTitle: string
  emptyBody: string
  searchPlaceholder: string
  /** Accessible name of the search box; also its test handle. */
  searchLabel: string
  /** Stat tiles over the whole event set; clicking one filters by `primaryOf`. */
  stats: (events: E[]) => StatTile[]
  /** Which stat-tile bucket an event belongs to. */
  primaryOf: (event: E) => P
  /** Heading of the frequency bar list. */
  topTitle: string
  /** The bar-list dimension; also the second cross-filter. */
  secondaryOf: (event: E) => string
  /**
   * Optional: rank that dimension somewhere other than the loaded slice.
   * Omit it and the bar list is counted in the browser over `visible`, as it
   * always was.
   */
  useRanking?: UseCorrelationRanking<P>
  /**
   * Optional: bucket the volume chart somewhere other than the loaded slice.
   * Omit it and the bars are counted in the browser over `visible`, as they
   * always were.
   */
  useHistogram?: UseCorrelationHistogram<P>
  /** Free-text match against an already-lowercased needle. */
  matches: (event: E, needle: string) => boolean
  /** Epoch milliseconds for the histogram and the sort, or null. */
  timeOf: (event: E) => number | null
  /** Artifact this event came from. */
  artifactIdOf: (event: E) => string
  /** Stable react key; events from different types can share an artifact id. */
  rowKey: (event: E) => string
  /** Table headers, excluding the trailing artifact column. */
  columns: string[]
  /** Leading cells for one row, excluding the trailing artifact column. */
  renderCells: (event: E) => ReactNode
}

/**
 * The filter state a ranking hook is asked to answer for. `search` is the raw
 * box contents; trim it before treating it as a needle, exactly as the page
 * does.
 */
export interface CorrelationRankingState<P extends string> {
  caseId: string
  primary: P | null
  secondary: string | null
  search: string
  /** True when any type's fan-out hit its page cap. */
  truncated: boolean
}

/**
 * A ranking for the frequency bar list, together with the label that says which
 * population produced it.
 */
export interface CorrelationRanking {
  /**
   * Items to draw, or null to keep ranking the visible slice in the browser.
   *
   * A non-null value is an assertion that these counts are exact over the
   * population `note` describes — the truncation banner drops its "the ORDER
   * can be wrong" clause when it sees one, so a hook must not return items it
   * only believes to be right.
   */
  items: TopItem[] | null
  /** Heading for the bar list. Must state which population it covers. */
  title: string
  /** Sentence under the bars naming that population exactly. */
  note?: ReactNode
}

/**
 * An opt-in replacement for the in-browser ranking, supplied per config.
 *
 * This is a React hook: the factory calls it unconditionally on every render of
 * the page it builds. It is opt-in rather than baked in because only some
 * correlation dimensions have a server-side aggregation behind them —
 * communications rank by counterparty, which the API can count in SQL, while
 * execution ranks by program name, which nothing counts but this page. A config
 * that supplies no hook must behave exactly as it did before the hook existed.
 */
export type UseCorrelationRanking<P extends string> = (
  state: CorrelationRankingState<P>,
) => CorrelationRanking | null

/**
 * The no-op used when a config opts out. Returning null means "rank the visible
 * slice in the browser and label it the way this page always has".
 */
function useNoRanking(): CorrelationRanking | null {
  return null
}

/**
 * A volume-over-time chart, together with the label that says which population
 * produced it.
 *
 * The parallel with `CorrelationRanking` is exact and deliberate: `buckets`
 * non-null is an assertion that these bars are counted over the population
 * `note` describes rather than over the slice this page loaded, and an EMPTY
 * array is still such an assertion — "nothing in that wider population could be
 * placed here" is an answer about it, and demoting it to the slice wording
 * would have the cap banner tell an examiner that these bars came from the
 * loaded slice when they did not.
 */
export interface CorrelationHistogram {
  /** Periods to draw, or null to keep bucketing the visible slice in the browser. */
  buckets: HistoBucket[] | null
  /** Width of every period in milliseconds. Null where there are no bars. */
  bucketMs: number | null
  /** Heading for the chart. Must state which population it covers. */
  title: string
  /** Sentence under the bars naming that population exactly. */
  note?: ReactNode
  /**
   * Drawn in place of the bars when `buckets` is an empty array. An empty chart
   * that could mean either "nothing happened" or "nothing could be placed" is
   * the failure this whole surface exists to avoid, and only the hook knows
   * which of those it is looking at.
   */
  emptyNote?: ReactNode
}

/**
 * An opt-in replacement for the in-browser bucketing, supplied per config.
 *
 * A React hook, called unconditionally by the factory, opt-in for the same
 * reason `useRanking` is: only some of these views have a server-side count of
 * their own volume behind them. A config that supplies no hook must behave
 * exactly as it did before the hook existed.
 */
export type UseCorrelationHistogram<P extends string> = (
  state: CorrelationRankingState<P>,
) => CorrelationHistogram | null

/**
 * The no-op used when a config opts out. Returning null means "bucket the
 * visible slice in the browser and leave the chart labelled as it always was".
 */
function useNoHistogram(): CorrelationHistogram | null {
  return null
}

export function makeCorrelationPage<E, P extends string>(
  config: CorrelationConfig<E, P>,
) {
  // Bound once, outside the component, so the hook this page calls is fixed for
  // that component's whole lifetime — a config is constant, so this is a
  // compile-time choice dressed as a runtime one, and the call below is
  // unconditional.
  const useRanking = config.useRanking ?? useNoRanking
  const useHistogram = config.useHistogram ?? useNoHistogram

  function CorrelationPage({ caseId: caseIdProp }: { caseId?: string } = {}) {
    const params = useParams() as { caseId?: string }
    const caseId = caseIdProp ?? (params.caseId as string)
    // The queries are case-keyed, but these cross-filters are page state and
    // the page stays mounted across a `:caseId` route change. A value picked in
    // case A almost never matches case B, so case B renders as an empty or
    // heavily-trimmed subset presented as the full picture (BUG-282).
    //
    // Clearing them in a `useEffect` keyed on the case left one COMMITTED
    // frame: when case B's records are already cached the switch renders and
    // paints case B's evidence through case A's filters — an examiner glancing
    // at the page reads "there is nothing here" for a case that has plenty —
    // and the effect only corrects it after the paint. Scoping the filters to
    // the case resolves them during render, so that frame cannot exist
    // (B2-145/B2-146).
    const [primary, setPrimary] = useEntityScopedState<P | null>(caseId, null)
    const [secondary, setSecondary] = useEntityScopedState<string | null>(
      caseId,
      null,
    )
    const [search, setSearch] = useEntityScopedState(caseId, '')

    const queries = useQueries({
      queries: config.types.map((t) => ({
        queryKey: [config.queryKey, caseId, t],
        queryFn: () => getAllRecords(caseId, t, { maxPages: MAX_PAGES }),
        staleTime: Infinity,
      })),
    })
    const updatedKey = queries.map((q) => q.dataUpdatedAt).join('|')
    const pending = queries.some((q) => q.isPending)
    // A single failed type must not blank the whole view — the others carry
    // real evidence. Only treat the page as failed when every type errored.
    const failedCount = queries.filter((q) => q.isError).length
    const allFailed = failedCount === queries.length
    // getAllRecords caps each type at maxPages; if any type hit the cap,
    // counts, histograms and the table under-report and the examiner must be
    // told.
    const anyTruncated = queries.some((q) => q.data?.truncated)

    // Asked before the early returns, like every other hook here. A config that
    // opts out gets `null` and everything below reads exactly as it did.
    const ranking = useRanking({
      caseId,
      primary,
      secondary,
      search,
      truncated: anyTruncated,
    })
    // The one claim the rest of the page keys off: a hook that handed us items
    // has counted them over more than the loaded slice. An empty list still
    // counts — "nobody matched" is a fact about that wider population, and
    // demoting it to the slice wording would have the cap banner tell the
    // examiner that the bars below were computed from the loaded slice when
    // they were not.
    const rankingIsExact = ranking?.items != null
    // An exact ranking with nothing in it, which `TopBars` would render as
    // nothing at all — heading included — leaving the provenance note stranded.
    const rankingIsEmpty = ranking?.items != null && ranking.items.length === 0
    const rankingTitle =
      ranking?.title ??
      (anyTruncated
        ? `${config.topTitle} (within the loaded slice)`
        : config.topTitle)

    // Asked here for the same reason the ranking is, and read the same way: a
    // hook that handed us buckets has counted them over more than the loaded
    // slice, and an empty array still counts as such an answer.
    const histogram = useHistogram({
      caseId,
      primary,
      secondary,
      search,
      truncated: anyTruncated,
    })
    const histogramIsExact = histogram?.buckets != null

    const events = useMemo(
      () =>
        config.types.flatMap((t, i) =>
          config.normalize(t, queries[i].data?.records ?? []),
        ),
      // eslint-disable-next-line react-hooks/exhaustive-deps
      [updatedKey],
    )

    // How many raw records the fan-out actually returned. Normalisation drops
    // every record that carries no correlation key, so this is the difference
    // between "this case has none of these" and "we loaded rows this view
    // cannot place".
    const loadedCount = useMemo(
      () => queries.reduce((n, q) => n + (q.data?.records.length ?? 0), 0),
      // eslint-disable-next-line react-hooks/exhaustive-deps
      [updatedKey],
    )

    // The parsers stamp `content_incomplete` on a record whose body they could
    // not fully recover and `inventory_incomplete` on a listing they had to cut
    // short. Normalisation keeps only the correlation fields, so the pair is
    // read off the raw records before that projection — otherwise a truncated
    // database would arrive here as a smaller set of complete-looking rows and
    // the histogram would read as the whole picture.
    const incompleteness = useMemo(
      () => summarizeIncompleteness(queries.flatMap((q) => q.data?.records ?? [])),
      // eslint-disable-next-line react-hooks/exhaustive-deps
      [updatedKey],
    )

    const stats = useMemo(() => config.stats(events), [events])

    const visible = useMemo(() => {
      const needle = search.trim().toLowerCase()
      return events.filter((e) => {
        if (primary && config.primaryOf(e) !== primary) return false
        if (secondary && config.secondaryOf(e) !== secondary) return false
        if (needle && !config.matches(e, needle)) return false
        return true
      })
    }, [events, primary, secondary, search])

    const times = useMemo(
      () => visible.map(config.timeOf).filter((t): t is number => t != null),
      [visible],
    )

    // The records this view holds and cannot place in time. The filter above
    // discarded them with no counter anywhere on the page, while the toolbar
    // beside the chart went on counting them in its "N of M events" — so the
    // figure an examiner reads as the chart's total was already short by an
    // amount nothing on screen stated. It is stated now.
    const untimed = visible.length - times.length

    const topItems = useMemo(() => {
      const counts = new Map<string, number>()
      for (const e of visible) {
        const label = config.secondaryOf(e)
        counts.set(label, (counts.get(label) ?? 0) + 1)
      }
      return Array.from(counts, ([label, count]) => ({ label, count }))
    }, [visible])

    const sorted = useMemo(
      () =>
        [...visible].sort(
          (a, b) => (config.timeOf(b) ?? 0) - (config.timeOf(a) ?? 0),
        ),
      [visible],
    )

    /**
     * Why what is on screen may be short of the evidence. Rendered above the
     * table AND above the empty state: a fan-out where most types errored and
     * the rest came back empty used to render as a bare "nothing here", which
     * is the one sentence the page must never say when it does not know
     * (the all-failed guard only catches the case where every type errored).
     */
    const statusNotes = (
      <>
        {failedCount > 0 && (
          <div className="error-note" role="note">
            {failedCount} of {queries.length} {config.sourceNoun} failed to load;
            the results below are incomplete. Retry or check the server.
          </div>
        )}
        {anyTruncated && (
          <div className="error-note" role="note">
            {/* Two things on this screen can each be answered exactly or fall
                back to the loaded slice, and they fetch INDEPENDENTLY — so this
                is a 2x2 of states, not a sentence with a clause in it. Every
                branch has to say, of every element on the page, which of the
                two populations it was computed over; a banner that condemned
                the whole screen once the histogram became exact would be as
                wrong as one that absolved it. */}
            {rankingIsExact && histogramIsExact ? (
              <>
                Some {config.sourceNoun} hit the per-type load cap. The stat
                tiles and the table of individual records below are computed
                over that loaded slice and under-report. The “{config.topTitle}”
                ranking and the histogram are the exceptions: neither is
                computed from the slice, and the note beneath each states the
                population it does cover. Do not read those two exact answers as
                evidence that the rest of this screen is complete — open the
                specific record type before relying on the rest.
              </>
            ) : rankingIsExact ? (
              <>
                Some {config.sourceNoun} hit the per-type load cap. The stat
                tiles, the histogram and the table of individual records below
                are all computed over that loaded slice and under-report. The
                “{config.topTitle}” ranking is the exception: it is not computed
                from the slice at all, and the note beneath it states the
                population it does cover. Do not read that one exact figure as
                evidence that the rest of this screen is complete — open the
                specific record type before relying on the rest.
              </>
            ) : histogramIsExact ? (
              <>
                Some {config.sourceNoun} hit the per-type load cap. The stat
                tiles and the table of individual records below are computed
                over that loaded slice and under-report, and the “
                {config.topTitle}” ranking is computed over it too, so the ORDER
                can be wrong there, not just the totals: a party that looks
                busiest may not be. The histogram is the exception: it is not
                computed from the slice at all, and the note beneath it states
                the population it does cover. Do not read that one exact chart
                as evidence that the rest of this screen is complete — open the
                specific record type before relying on the rest.
              </>
            ) : (
              <>
                Some {config.sourceNoun} hit the per-type load cap. Counts and
                charts under-report — and the ranking below is computed over the
                loaded slice, so the ORDER can be wrong, not just the totals: a
                party that looks busiest here may not be. Narrow with filters or
                open the specific record type before relying on it.
              </>
            )}
          </div>
        )}
        <IncompletenessBanner summary={incompleteness} noun={config.recordNoun} />
      </>
    )

    if (pending) {
      return (
        <div>
          <h1 className="page-title">{config.title}</h1>
          <div className="loading">{config.loadingLabel}</div>
        </div>
      )
    }

    // A failed load must not masquerade as "nothing here" — that would let an
    // examiner conclude there is no evidence when the query actually errored.
    if (allFailed) {
      return (
        <div>
          <h1 className="page-title">{config.title}</h1>
          <div className="error-note">
            Failed to load {config.subjectNoun}. This is a load error, not an
            empty result — retry or check the server.
          </div>
        </div>
      )
    }

    if (events.length === 0) {
      return (
        <div>
          <h1 className="page-title">{config.title}</h1>
          {/* Records the parsers could not finish are dropped by normalisation
              (nothing to correlate on), so an empty view can be the tail end of
              a truncated parse rather than a machine that did none of this. The
              banner and the notes above are what keep those apart. */}
          {statusNotes}
          {loadedCount > 0 && (
            <div className="warn-note" role="note">
              {formatCount(loadedCount)}{' '}
              {loadedCount === 1 ? 'record was' : 'records were'} loaded for
              these {config.sourceNoun}, but none carried{' '}
              {config.correlationKeyNoun}, so none could be placed on this view.
              This is not a statement that there were none — open the individual
              record types to read them.
            </div>
          )}
          <div className="empty-state">
            <h3>{config.emptyTitle}</h3>
            <p>{config.emptyBody}</p>
          </div>
        </div>
      )
    }

    const shown = sorted.slice(0, TABLE_CAP)

    return (
      <div className="rv">
        <h1 className="page-title">{config.title}</h1>
        <p className="rv-note">{config.intro}</p>

        {statusNotes}

        <div className="rv-toolbar">
          <input
            className="input rv-search"
            placeholder={config.searchPlaceholder}
            aria-label={config.searchLabel}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <span className="rv-count">
            {formatCount(visible.length)}
            {primary || secondary || search.trim()
              ? ` of ${formatCount(events.length)}`
              : ''}{' '}
            events
          </span>
          {(primary || secondary) && (
            <button
              type="button"
              className="link-button"
              onClick={() => {
                setPrimary(null)
                setSecondary(null)
              }}
            >
              Clear filters
            </button>
          )}
        </div>

        <StatTiles
          tiles={stats}
          active={primary}
          onToggle={(k) => setPrimary((cur) => (cur === k ? null : (k as P)))}
        />

        {histogram?.buckets != null ? (
          <EventHistogram
            buckets={histogram.buckets}
            bucketMs={histogram.bucketMs}
            title={histogram.title}
            empty={histogram.emptyNote}
            note={histogram.note}
          />
        ) : (
          <TimeHistogram
            times={times}
            untimed={untimed}
            title={histogram?.title}
            note={histogram?.note}
          />
        )}

        <div className="rv-dims">
          {rankingIsEmpty ? (
            // `TopBars` draws nothing at all for an empty list, which is right
            // for a bar chart and wrong for an exact ranking: the provenance
            // note below carries case-wide totals an examiner may quote, and
            // without a heading over it those totals sit on the page attached
            // to nothing. A ranking that matched nobody is still an answer
            // about the population the note describes, so it is stated as one
            // rather than left to be inferred from a blank space.
            <div className="rv-top">
              <div className="rv-top-title">{rankingTitle}</div>
              <p className="rv-note" role="note">
                This ranking has no entries. That is its answer about the
                population described below, not a ranking that failed to load.
              </p>
            </div>
          ) : (
            <TopBars
              title={rankingTitle}
              items={ranking?.items ?? topItems}
              active={secondary}
              onSelect={(label) =>
                setSecondary((cur) => (cur === label ? null : label))
              }
            />
          )}
        </div>
        {/* Kept outside `rv-dims` so it runs the full width under the bars
            rather than becoming a second column of that grid. */}
        {ranking?.note && (
          <p className="rv-note rv-rank-note" role="note">
            {ranking.note}
          </p>
        )}

        <table className="data-table an-table rv-table">
          <thead>
            <tr>
              {config.columns.map((c) => (
                <th key={c}>{c}</th>
              ))}
              <th>Artifact</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((e) => (
              <tr key={config.rowKey(e)} tabIndex={0}>
                {config.renderCells(e)}
                <td>
                  <ArtifactLink caseId={caseId} id={config.artifactIdOf(e)}>
                    open
                  </ArtifactLink>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {visible.length > TABLE_CAP && (
          <p className="rv-note">
            Showing the first {formatCount(TABLE_CAP)} of{' '}
            {formatCount(visible.length)} events. Narrow with the filters
            above.
          </p>
        )}
      </div>
    )
  }
  CorrelationPage.displayName = `CorrelationPage(${config.queryKey})`
  return CorrelationPage
}
