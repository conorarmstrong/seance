import { useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Q_KEYS_MAX, type ParsedRecord, type RecordMetadata } from "./api";
import {
  SEARCH_DEBOUNCE_MS,
  useDebounced,
  useRecordPages,
} from "./recordPages";
import { toEpochMs } from "../../lib/epoch";
import { useInfiniteScroll } from "../../lib/useInfiniteScroll";
import { RecordTable, type RecordTableSort } from "./RecordTable";
import type { Column } from "./cells";
import {
  StatTiles,
  TimeHistogram,
  TopBars,
  type StatTile,
  type TopItem,
} from "./RichCharts";
import {
  IncompletenessBanner,
  useIncompleteness,
} from "../../components/Incompleteness";
import { ChartScopeNote, SearchScopeNote } from "./searchScope";
import type { ViewerProps } from "./viewers";
import { formatCount } from "../../lib/format";

const NONE = "(none)";
/** Records fetched per scroll step. */
const RECORD_PAGE_SIZE = 200;

/**
 * The ordering a viewer opens on: none.
 *
 * A null sort key means the server's own INGEST order, which is not event order
 * and must never be labelled "most recent" — so no column carries an arrow
 * until the examiner asks one to, and no `order` is sent for an ordering that
 * orders on nothing.
 */
const INGEST_ORDER: RecordTableSort = { key: null, order: "asc" };

/** One frequency dimension rendered as a clickable top-N bar list. */
export interface RichDimension {
  title: string;
  /** Bucket a record into a label for this dimension; null → excluded. */
  value: (meta: RecordMetadata) => string | null;
  /** Optional per-record weight (e.g. run_count, file_size). Defaults to 1, so
   * bars rank by record count; with a weight they rank by summed magnitude. */
  weight?: (meta: RecordMetadata) => number;
}

export interface RichConfig {
  /** Metadata keys holding the primary timestamp (unix seconds or ISO). */
  timeKeys?: string[];
  /** Drop records before analysis (e.g. summary rows). Return true to drop. */
  drop?: (meta: RecordMetadata) => boolean;
  /** Stat tiles over the dataset; each also filters when clicked. */
  stats?: (records: ParsedRecord[]) => StatTile[];
  /** Which stat key a record belongs to (for stat-tile filtering). */
  statOf?: (meta: RecordMetadata) => string | null;
  /** Frequency dimensions shown as bar lists. */
  dimensions?: RichDimension[];
  /** Table columns. */
  columns: Column[];
  /** Highlight: a returned reason marks the row notable. */
  notable?: (meta: RecordMetadata) => string | null;
  /**
   * Bare metadata keys the Filter box's term is tested against, SERVER-side.
   * These go over the wire as `q_keys`: the endpoint refuses a term without
   * them rather than guessing which fields it applies to, and refuses more than
   * `Q_KEYS_MAX` of them rather than trimming the list.
   */
  searchKeys?: string[];
  /** Empty-state noun, e.g. "event log entries". */
  noun: string;
}

function topItems(
  records: ParsedRecord[],
  value: (m: RecordMetadata) => string | null,
  weight?: (m: RecordMetadata) => number,
): TopItem[] {
  const counts = new Map<string, number>();
  for (const r of records) {
    const label = value(r.metadata);
    if (label == null) continue;
    const w = weight ? weight(r.metadata) : 1;
    counts.set(label, (counts.get(label) ?? 0) + w);
  }
  return Array.from(counts, ([label, count]) => ({ label, count }));
}

/**
 * Build a rich analytics viewer for a ParsedRecord type: stat tiles, a
 * volume-over-time histogram, frequency bars, and a filterable, highlightable
 * table. Stat tiles and bar rows act as one-click cross-filters.
 *
 * The Filter box is a SERVER query. `GET /cases/:id/records` takes `q` and
 * `q_keys`, so a term is tested against every record of the type and `total`
 * comes back as the matching population — which is why an empty table under a
 * term is now a finding about the case rather than a finding about how far the
 * examiner had scrolled. The toolbar's old caveat existed precisely because the
 * term only ever reached the loaded rows; it has been deleted rather than
 * softened, and `SearchScopeNote` states what is true of the query instead.
 *
 * The stat tiles, the histogram and the bars did NOT move. They are still
 * computed in this browser over the rows loaded so far, so they keep their own
 * sentence (`ChartScopeNote`) whenever more matching records exist than have
 * been fetched. Two different limitations, two different sentences, and the one
 * that no longer applies is gone.
 */
export function makeRichViewer(config: RichConfig) {
  const RichViewer = function RichViewer({
    caseId,
    type,
  }: ViewerProps): ReactNode {
    const [stat, setStat] = useState<string | null>(null);
    const [dim, setDim] = useState<{ title: string; label: string } | null>(
      null,
    );
    const [search, setSearch] = useState("");

    // The term as it will be sent. Held back until typing settles, because
    // every distinct value is a fresh query key and therefore a fresh request.
    const term = useDebounced(search.trim(), SEARCH_DEBOUNCE_MS);
    // The endpoint refuses a longer list rather than trimming it, so a viewer
    // that declared more keys than it accepts must not send them all. None does
    // today; the slice is here so that adding a seventeenth key to a config
    // cannot turn every search on that type into a 400.
    const searchKeys = useMemo(
      () => config.searchKeys?.slice(0, Q_KEYS_MAX) ?? [],
      [],
    );
    const searching = term.length > 0 && searchKeys.length > 0;
    const [sort, setSort] = useState<RecordTableSort>(INGEST_ORDER);

    // Rows stream in a page at a time as the table is scrolled, rather than the
    // viewer pulling a fixed slab of the case up front. The term AND the
    // ordering are part of the query key: either one changed is a different
    // question of the server, and its answer has to replace the previous one's
    // pages rather than be appended to them — which is also what puts paging
    // back at page 1 whenever either changes.
    // A record a later run answered is the previous answer, not a second one,
    // so the listing leaves it out until asked (HUNT-107).
    const [showSuperseded, setShowSuperseded] = useState(false);

    const {
      query,
      records,
      total,
      typeTotal,
      unfilterable,
      qMatch,
      supersededTotal,
    } = useRecordPages({
      caseId,
      type,
      pageSize: RECORD_PAGE_SIZE,
      q: searching ? term : undefined,
      qKeys: searching ? searchKeys : undefined,
      sort: sort.key ?? undefined,
      order: sort.order,
      includeSuperseded: showSuperseded,
      queryKey: [
        "rich-records",
        type,
        caseId,
        searching ? term : null,
        sort.key,
        sort.order,
        showSuperseded,
      ],
    });

    // Counted before `drop`: this is what was fetched, and it is what the "N of
    // T loaded" note in the toolbar is about.
    const loadedCount = records.length;

    const all = useMemo(
      () =>
        config.drop
          ? records.filter((r) => !config.drop!(r.metadata))
          : records,
      [records],
    );

    // Pull the next page when the end of the table scrolls into view.
    const endRef = useRef<HTMLDivElement>(null);
    const { hasNextPage, isFetchingNextPage, fetchNextPage } = query;
    useInfiniteScroll(endRef, {
      hasNextPage,
      isFetchingNextPage,
      onLoadMore: fetchNextPage,
    });

    const stats = useMemo(() => config.stats?.(all) ?? [], [all]);
    const incompleteness = useIncompleteness(all);

    // The term is NOT applied here. The server applied it, so these rows already
    // ARE the matching ones; re-testing them in the browser would narrow the
    // server's answer with a different matcher — the browser folds Unicode case,
    // SQLite's LIKE folds ASCII — and produce a count that agrees with nothing.
    // What remains are the stat tile and the bar row, which are cross-filters
    // over the loaded rows, exactly as `ChartScopeNote` says.
    const visible = useMemo(() => {
      if (!stat && !dim) return all;
      return all.filter((r) => {
        const m = r.metadata;
        if (stat && config.statOf && config.statOf(m) !== stat) return false;
        if (dim) {
          const d = config.dimensions?.find((x) => x.title === dim.title);
          if (d && (d.value(m) ?? NONE) !== dim.label) return false;
        }
        return true;
      });
    }, [all, stat, dim]);

    const times = useMemo(
      () =>
        config.timeKeys
          ? visible
              .map((r) => toEpochMs(r.metadata, config.timeKeys!))
              .filter((t): t is number => t != null)
          : [],
      [visible],
    );

    const dims = useMemo(
      () =>
        (config.dimensions ?? []).map((d) => ({
          title: d.title,
          items: topItems(visible, d.value, d.weight),
        })),
      [visible],
    );

    // The toolbar has to survive a search. A new term is a new query key, so
    // react-query reports `isPending` again — and an early return on that would
    // unmount the Filter box mid-word, taking the caret, the term and the
    // examiner's place with it. Once anything has loaded the shell stays, and
    // only the results area below it says that a search is running.
    const everLoaded = useRef(false);
    if (query.data) everLoaded.current = true;

    if (query.isError) {
      return <div className="error-note">{(query.error as Error).message}</div>;
    }
    if (query.isPending && !everLoaded.current) {
      return <div className="loading">Loading {config.noun}…</div>;
    }
    // "No records of this type were parsed" is a claim about the evidence, so it
    // is allowed only when nothing was asked of the server but the type itself.
    // Under a term an empty result is an empty RESULT, and saying it there would
    // turn a filter that found nothing into a finding that nothing exists.
    if (!searching && !query.isPending && all.length === 0) {
      return (
        <div className="empty-state">
          <h3>No {config.noun}</h3>
          <p>No {config.noun} were parsed for this case.</p>
        </div>
      );
    }

    // Clicking the active column reverses it; a new column starts in whichever
    // direction that column declared it is usually read in.
    const onSort = (key: string) =>
      setSort((cur) =>
        cur.key === key
          ? { key, order: cur.order === "asc" ? "desc" : "asc" }
          : {
              key,
              order:
                config.columns.find((c) => c.sortKey === key)
                  ?.sortDefaultOrder ?? "asc",
            },
      );

    const crossFiltered = stat != null || dim != null;
    const shown = visible;
    // The charts are still browser-side, so they describe the loaded rows
    // whenever fewer have been fetched than the query matched.
    const partial = loadedCount < total;

    return (
      <div className="rv">
        {/* This viewer loads its own records, so the page shell's banner (over its
          page-1 fetch) does not describe what is on screen here. The parsers
          stamp the standard pair on records they could not finish; read it over
          the set this viewer actually holds (B4-023/B4-024). */}
        <IncompletenessBanner summary={incompleteness} noun={config.noun} />
        <div className="rv-toolbar">
          {config.searchKeys && (
            <input
              className="input rv-search"
              placeholder="Filter…"
              aria-label={`Filter ${config.noun}`}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          )}
          <span className="rv-count">
            {/* A count of the RENDERED rows. A stat tile or a bar row narrows the
                loaded set in the browser, so both halves of this reading are
                about loaded rows and it says so; the case's own populations are
                in the note beside it. */}
            {crossFiltered
              ? `${formatCount(visible.length)} of ${formatCount(all.length)} loaded rows shown`
              : `${formatCount(visible.length)} shown`}
          </span>
          {crossFiltered && (
            <button
              type="button"
              className="link-button"
              onClick={() => {
                setStat(null);
                setDim(null);
              }}
            >
              Clear filters
            </button>
          )}
          <span className="rv-note">
            {formatCount(loadedCount)} of {formatCount(total)}
            {searching ? " matching" : ""} loaded
          </span>
        </div>

        {!query.isPending && (supersededTotal ?? 0) > 0 && (
          <p className="rv-note" role="note" data-testid="rv-superseded-note">
            {formatCount(supersededTotal ?? 0)} {config.noun} from an earlier
            run of this parser are not listed: a later run answered them, and
            they are kept as history rather than counted again. The numbers
            above are of the current run.{" "}
            <button
              type="button"
              className="link-button"
              onClick={() => setShowSuperseded(true)}
            >
              Show the earlier run&rsquo;s records
            </button>
          </p>
        )}
        {!query.isPending && showSuperseded && (
          <p className="rv-note" role="note" data-testid="rv-superseded-shown">
            Showing the earlier run&rsquo;s records alongside the current ones;
            each is marked in the Status column.{" "}
            <button
              type="button"
              className="link-button"
              onClick={() => setShowSuperseded(false)}
            >
              Hide them again
            </button>
          </p>
        )}

        {searching && !query.isPending && (
          <SearchScopeNote
            term={term}
            keys={searchKeys}
            matching={total}
            typeTotal={typeTotal}
            unfilterable={unfilterable}
            match={qMatch}
            noun={config.noun}
          />
        )}

        {query.isPending ? (
          <div className="loading">Searching {config.noun}…</div>
        ) : all.length === 0 ? (
          // A term that matched nothing. The sentence above already names both
          // populations, so this only has to be an empty state that does not
          // read as absence from the case.
          <div className="empty-state">
            <h3>No matching {config.noun}</h3>
            <p>
              No {config.noun} in this case match &ldquo;{term}&rdquo;. Clear
              the filter to see all {formatCount(typeTotal)}.
            </p>
          </div>
        ) : (
          <>
            {partial && (
              <ChartScopeNote
                loaded={loadedCount}
                total={total}
                noun={config.noun}
                filtered={searching}
              />
            )}

            {stats.length > 0 && (
              <StatTiles
                tiles={stats}
                active={stat}
                onToggle={(k) => setStat((cur) => (cur === k ? null : k))}
              />
            )}

            {config.timeKeys && <TimeHistogram times={times} />}

            {dims.some((d) => d.items.length > 0) && (
              <div className="rv-dims">
                {dims.map((d) => (
                  <TopBars
                    key={d.title}
                    title={d.title}
                    items={d.items}
                    active={dim?.title === d.title ? dim.label : null}
                    onSelect={(label) =>
                      setDim((cur) =>
                        cur && cur.title === d.title && cur.label === label
                          ? null
                          : { title: d.title, label },
                      )
                    }
                  />
                ))}
              </div>
            )}

            {/* One shared record table: windowed DOM, one tab stop, arrow-key
                movement over the whole set. See RecordTable. */}
            <RecordTable
              records={shown}
              caseId={caseId}
              columns={config.columns}
              notable={config.notable}
              className="rv-table"
              sort={sort}
              onSort={onSort}
            />
            <div ref={endRef} className="rv-sentinel">
              {hasNextPage && (
                <button
                  type="button"
                  className="link-button"
                  onClick={() => void fetchNextPage()}
                  disabled={isFetchingNextPage}
                >
                  {isFetchingNextPage ? "Loading more…" : "Load more"}
                </button>
              )}
            </div>
          </>
        )}
      </div>
    );
  };
  // This viewer fetches its own records, so it is the one that can say how many
  // an earlier run left and show them; the page shell stands down (HUNT-107).
  RichViewer.rendersSupersededNote = true;
  return RichViewer;
}
