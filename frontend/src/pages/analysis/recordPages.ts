import { useEffect, useMemo, useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { getRecords, type ParsedRecord, type SortOrder } from "./api";

/**
 * How long a record filter box waits before asking the server. The filter is a
 * query now, so a keystroke is a round trip; this is what makes typing one
 * question rather than six.
 */
export const SEARCH_DEBOUNCE_MS = 250;

/**
 * Hold `value` back until it has stopped changing for `delayMs`.
 *
 * A record filter is now a server query, and a query fired on every keystroke
 * would put ten requests in flight for a six-letter term and paint whichever
 * one landed last. The delay is what turns typing into one question.
 */
export function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}

/**
 * Scroll-paged ParsedRecords for one type.
 *
 * Rows stream in a page at a time as the list is scrolled, rather than a viewer
 * pulling a fixed slab of the case up front. Every caller pairs this with a
 * count of what it holds against `total` — the paging is only honest because
 * the shortfall is on screen.
 *
 * `q`/`qKeys` and `sort`/`order` are the server's own filter and ordering, so
 * a viewer that passes them is filtering and sorting the whole record type
 * rather than the rows it happens to be holding. They are NOT part of the
 * query key automatically: the caller owns the key, and must put them in it,
 * because changing either asks a different question and the answer must not be
 * appended to the previous one's pages.
 */
export function useRecordPages({
  caseId,
  type,
  sourceId,
  pageSize,
  queryKey,
  enabled,
  q,
  qKeys,
  sort,
  order,
  includeSuperseded,
}: {
  caseId: string | undefined;
  type: string | undefined;
  /** Restrict to records under this source acquisition's subtree. */
  sourceId?: string;
  pageSize: number;
  queryKey: readonly unknown[];
  enabled?: boolean;
  /** Server-side substring term. Sent only together with `qKeys`. */
  q?: string;
  /** Bare metadata keys the term is tested against. */
  qKeys?: string[];
  /** Bare metadata key to order by. Absent means ingest order. */
  sort?: string;
  order?: SortOrder;
  /** Include the records a later run answered (HUNT-107). */
  includeSuperseded?: boolean;
}) {
  const query = useInfiniteQuery({
    queryKey,
    initialPageParam: 1,
    queryFn: ({ pageParam }) =>
      getRecords(caseId!, {
        type: type!,
        page: pageParam as number,
        page_size: pageSize,
        source_id: sourceId,
        q,
        q_keys: qKeys,
        sort,
        order,
        include_superseded: includeSuperseded,
      }),
    getNextPageParam: (last, pages) => {
      // A page that came back empty is the end of the set, whatever `total`
      // says. Without this the three copies of this query would keep asking for
      // the next page forever when a total outran the rows the server could
      // produce: the sentinel stays in view, each fetch appends nothing, and
      // the request storm never ends. Stopping here leaves the shortfall
      // visible in the "N of T loaded" counts, which is the honest reading.
      if (last.records.length === 0) return undefined;
      const loaded = pages.reduce((n, p) => n + p.records.length, 0);
      return loaded < last.total ? pages.length + 1 : undefined;
    },
    enabled,
  });

  const records = useMemo(
    () => (query.data?.pages ?? []).flatMap((p) => p.records),
    [query.data],
  );

  const first = query.data?.pages[0];

  return {
    query,
    /** Every record loaded so far, in page order. */
    records: records as ParsedRecord[],
    /**
     * The server's count for the set this query asked about. With `q` applied
     * that is the MATCHING population, not the type's — see `typeTotal`.
     */
    total: first?.total ?? 0,
    /**
     * The type's own population, ignoring `q`. Falls back to `total` on a
     * server that does not publish it, which is exactly right: without a `q`
     * the two are the same number.
     */
    typeTotal: first?.type_total ?? first?.total ?? 0,
    /**
     * Records the filter could not be evaluated against — neither matches nor
     * established non-matches. `null` means the question was never asked, and
     * a caller must not render that as 0.
     */
    unfilterable: first?.unfilterable_metadata ?? null,
    /**
     * How the server says it matched. Published by the endpoint precisely so a
     * client does not have to guess, and passed through rather than assumed:
     * a screen that described ASCII-only case folding when the server had
     * started folding Unicode would be making a claim about a search it did not
     * run. `null` from a server that does not publish it.
     */
    qMatch: first?.q_match ?? null,
    /**
     * Records of this type a later run of the module answered, left out of this
     * listing. `null` means nothing was excluded — the caller asked for them —
     * and must not be rendered as 0.
     */
    supersededTotal: first?.superseded_total ?? null,
  };
}
