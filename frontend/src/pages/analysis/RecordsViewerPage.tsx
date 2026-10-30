import { useRef, useState } from "react";
import { SkeletonTable } from "../../components/Skeleton";
import { downloadFile } from "../../lib/download";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import {
  IncompletenessBanner,
  useIncompleteness,
} from "../../components/Incompleteness";
import { useInfiniteScroll } from "../../lib/useInfiniteScroll";
import { useRecordPages } from "./recordPages";
import { humanizeType } from "./lib";
import { GenericViewer, VIEWERS } from "./viewers";
import { formatCount } from "../../lib/format";
import "./analysis.css";

/** Records fetched per scroll step for the simple (non-aggregate) viewers. */
const PAGE_SIZE = 100;

/**
 * Type-specific record viewer. Picks a tailored viewer from the registry by
 * the route `type`, falling back to a generic key/value table.
 */
export function RecordsViewerPage({
  caseId: caseIdProp,
  type: typeProp,
  source,
  embedded = false,
}: {
  caseId?: string;
  type?: string;
  /** Restrict to records from one source acquisition (provenance scoping). */
  source?: string;
  embedded?: boolean;
} = {}) {
  const params = useParams<{ caseId: string; type: string }>();
  const caseId = caseIdProp ?? params.caseId;
  const type = typeProp ?? params.type;
  // Rows stream in as the list is scrolled instead of the examiner paging by
  // hand; the aggregate viewers do their own loading. `source` is part of the
  // query key so switching acquisitions refetches rather than showing another
  // source's rows under this one's heading.
  // A record a later run of the same module answered is the previous answer,
  // not a second one, so the listing leaves it out until asked (HUNT-107).
  const [showSuperseded, setShowSuperseded] = useState(false);
  const [exporting, setExporting] = useState(false);
  // Shown beside the button rather than as a toast: this page is mounted by
  // every record-type viewer, and a provider it needed would be one every
  // mount site had to supply.
  const [exportError, setExportError] = useState<string | null>(null);
  const {
    query: recordsQuery,
    records,
    total,
    supersededTotal,
  } = useRecordPages({
    caseId,
    type,
    sourceId: source,
    pageSize: PAGE_SIZE,
    includeSuperseded: showSuperseded,
    queryKey: [
      "analysis-records",
      caseId,
      type,
      source ?? null,
      showSuperseded,
    ],
    enabled: !!caseId && !!type,
  });

  const data = recordsQuery.data?.pages[0];

  const endRef = useRef<HTMLDivElement>(null);
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = recordsQuery;
  useInfiniteScroll(endRef, {
    hasNextPage,
    isFetchingNextPage,
    onLoadMore: fetchNextPage,
  });

  const def = type && type in VIEWERS ? VIEWERS[type] : null;
  const Viewer = def?.Component ?? GenericViewer;
  const aggregate = def?.aggregate ?? false;
  // A viewer that loads its own records carries its own note about them: the
  // page's note would be about a different fetch, and its control would move
  // rows the viewer never asked for.
  const viewerOwnsSupersededNote =
    (Viewer as { rendersSupersededNote?: boolean }).rendersSupersededNote ===
    true;
  const label = type ? humanizeType(type) : "Records";

  // The parsers stamp `content_incomplete` / `inventory_incomplete` on records
  // they could not finish. Read here rather than in each of the ~15 viewers:
  // every one of them is mounted through this page, so a truncated database or
  // an undecodable row is announced once, in the same words, whichever viewer
  // the examiner opened.
  const incompleteness = useIncompleteness(records);

  // The whole type as a CSV: `GET /cases/{id}/records/export/csv` existed with
  // nothing in the UI reaching it. Scoped to the type and the source
  // acquisition, and to the current run's records, and to nothing else — a
  // term or sort a viewer holds is the viewer's, so the button says "all" and
  // the file's own preamble says the same. Bounded server-side to 100,000
  // rows, and the file carries a notice row when that ceiling binds.
  async function handleExportCsv() {
    if (!caseId || !type) return;
    setExporting(true);
    setExportError(null);
    try {
      const query = new URLSearchParams({ type });
      if (source) query.set("source_id", source);
      await downloadFile(
        `/cases/${caseId}/records/export/csv?${query.toString()}`,
        `records-${type}-${caseId}.csv`,
      );
    } catch (err) {
      setExportError(
        `CSV export failed${err instanceof Error && err.message ? `: ${err.message}` : ""}. Click Export all as CSV to retry.`,
      );
    } finally {
      setExporting(false);
    }
  }

  return (
    <div>
      {!embedded && (
        <Link className="an-back" to={`/cases/${caseId}/analysis`}>
          <ArrowLeft size={14} /> All record types
        </Link>
      )}
      <div className="an-viewer-head">
        <h1 className="page-title">{label}</h1>
        {data && (
          <span className="an-viewer-count">
            {/* An aggregate viewer loads its own data (conversations are
                aggregated server-side), so the page's own page-1 fetch says
                nothing useful about what the examiner is looking at. */}
            {!aggregate && records.length < total
              ? `${formatCount(records.length)} of ${formatCount(total)} records`
              : `${formatCount(total)} records`}
          </span>
        )}
        {data && !aggregate && total > 0 && (
          <button
            type="button"
            className="btn"
            disabled={exporting}
            onClick={() => void handleExportCsv()}
          >
            {exporting ? "Exporting…" : "Export all as CSV"}
          </button>
        )}
        {exportError && (
          <span className="error-note" role="alert">
            {exportError}
          </span>
        )}
      </div>

      {/* For an aggregate viewer this page fetches ONE page of records purely
          to decide what to mount; the viewer below loads its own, usually far
          more. Saying "the records this page checked" without saying how few
          that is let a stamp on record 300 of 4,000 go unmentioned while the
          sentence read as coverage. The viewers now carry their own banner over
          their own data (B4-023/B4-024); this one names its sample size so the
          two cannot be confused. */}
      {/* Written here rather than in each viewer: every type is mounted through
          this page, so "what an earlier run left" is said once, in the same
          words, whichever viewer opened. A viewer that fetches its own records
          says it for itself — it is the one that can also show them. */}
      {!viewerOwnsSupersededNote && (supersededTotal ?? 0) > 0 && (
        <p className="rv-note" role="note" data-testid="rv-superseded-note">
          {formatCount(supersededTotal ?? 0)} {label} records from an earlier
          run of this parser are not listed: a later run answered them, and they
          are kept as history rather than counted again. The count above is of
          the current run.{" "}
          {!aggregate && (
            <button
              type="button"
              className="link-button"
              onClick={() => setShowSuperseded(true)}
            >
              Show the earlier run&rsquo;s records
            </button>
          )}
        </p>
      )}
      {!viewerOwnsSupersededNote && showSuperseded && (
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

      <IncompletenessBanner
        summary={incompleteness}
        noun={`${label} records`}
        scopeNote={
          aggregate
            ? `This proportion is over the first ${formatCount(records.length)} of ${formatCount(total)} ${label} records only — the sample this page fetched to choose a viewer. The viewer below loads its own records and reports on those separately.`
            : undefined
        }
      />

      {recordsQuery.isPending && (
        <SkeletonTable rows={10} cols={6} label="Loading records" />
      )}
      {recordsQuery.isError && (
        <div className="error-note">{recordsQuery.error.message}</div>
      )}
      {data &&
        records.length === 0 &&
        // Paging stops at the first empty page whatever `total` claims, which
        // is what keeps a server that over-counts from being asked for page
        // 3, 4, 5 forever. That guard turned an unbounded spin into a screen
        // that SETTLES, so the sentence it settles on has to be true: with the
        // server reporting rows and serving none, "this case has no records of
        // this type" is a finding about the evidence drawn from a failure to
        // read it. Say which of the two happened.
        (total > 0 ? (
          <div className="error-note" role="note">
            The server reported {formatCount(total)} {label} records for this
            case but served none. This is an incomplete read, not an empty
            result — retry, and do not record this type as absent.
          </div>
        ) : (
          <div className="empty-state">
            <h3>No {label} records</h3>
            <p>This case has no records of this type.</p>
          </div>
        ))}
      {data && records.length > 0 && (
        <div className="panel">
          {/*
            Keyed on the case so a `:caseId` change remounts the viewer instead
            of leaving it mounted with the previous case's local state. Every
            viewer keeps some — a selected conversation, database, table or
            activity row, a client-side search string, a "load more" page cap —
            and none of it means anything under another case. A carried search
            string makes a populated case read as empty; a carried selection can
            latch onto a same-named thread or table in the new case and present
            it as the examiner's pick. Keying here fixes the whole family at the
            one place they are mounted, rather than in each viewer
            (B2-029/056/090/091/121).

            `type` is part of the key for the same reason: several record types
            share one Component reference (the four SRUM tables, the chat-media
            walls), so React keeps that instance mounted across a `:type` change
            and its search string and selection carry into a different record
            set — the same "this table looks empty" failure, inside one case.
          */}
          <Viewer
            key={`${caseId}/${type}`}
            records={records}
            caseId={caseId!}
            type={type!}
          />
          {!aggregate && (
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
          )}
        </div>
      )}
    </div>
  );
}
