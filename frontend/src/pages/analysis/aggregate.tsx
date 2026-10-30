import { useState } from 'react'
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useIncompleteness } from '../../components/Incompleteness'
import type { IncompletenessSummary } from '../../lib/incompleteness'
import { getAllRecords, type ParsedRecord } from './api'
import { formatCount } from '../../lib/format'

/** Pages added to the cap each time the examiner asks for more. */
const PAGE_STEP = 8

/** Stable identity so `useMemo` in a caller does not rerun on every render. */
const NO_RECORDS: ParsedRecord[] = []

export interface AggregateLoad {
  /** Records loaded so far; never null, so callers can filter unconditionally. */
  records: ParsedRecord[]
  /** The server's count for the whole type, which may exceed `records`. */
  total: number
  /** True when the page cap stopped the load short of `total`. */
  truncated: boolean
  /** The standard pair, read over the records this viewer actually holds. */
  incompleteness: IncompletenessSummary
  /** Raise the page cap and refetch. */
  loadMore: () => void
  /**
   * The loading or error node. Non-null means the viewer has no data to show
   * and must return this instead: an error rendered as an empty state is the
   * page telling an examiner there is nothing when it does not know.
   */
  gate: ReactNode | null
}

/**
 * The load shell shared by the aggregate viewers (agenda, mail, contacts,
 * calls). Those viewers pull the whole record type rather than a page, so each
 * one owned a copy of: the page cap, the cap-keyed query, the incompleteness
 * summary over its own records, and the loading/error gate. The summary is the
 * reason this is shared — a viewer that fetches its own records and reports the
 * page shell's numbers describes a different set than the one on screen
 * (B4-023/B4-024), and that was fixed four times by hand.
 */
export function useAggregatedRecords(
  caseId: string,
  type: string,
  opts: { queryKey: string; loadingLabel: string },
): AggregateLoad {
  const [pageCap, setPageCap] = useState(PAGE_STEP)
  const query = useQuery({
    queryKey: [opts.queryKey, caseId, type, pageCap],
    queryFn: () => getAllRecords(caseId, type, { maxPages: pageCap }),
  })

  const incompleteness = useIncompleteness(query.data?.records)

  return {
    records: query.data?.records ?? NO_RECORDS,
    total: query.data?.total ?? 0,
    truncated: query.data?.truncated ?? false,
    incompleteness,
    loadMore: () => setPageCap((c) => c + PAGE_STEP),
    gate: query.isPending ? (
      <div className="loading">{opts.loadingLabel}</div>
    ) : query.isError ? (
      <div className="error-note">{(query.error as Error).message}</div>
    ) : null,
  }
}

/**
 * "You are looking at the first N of T" plus the control that widens it.
 *
 * `shown` is the count the viewer actually listed, not the count it fetched:
 * the number an examiner is being asked to trust has to be the one on screen.
 */
export function LoadMoreNote({
  shown,
  total,
  noun,
  onLoadMore,
}: {
  shown: number
  total: number
  /** What is being counted ("events", "records"); omitted reads "First 3 of 9." */
  noun?: string
  onLoadMore: () => void
}) {
  return (
    <div className="an-chat-note">
      First {formatCount(shown)} of {formatCount(total)}
      {noun ? ` ${noun}` : ''}.
      <button type="button" className="link-button" onClick={onLoadMore}>
        Load more
      </button>
    </div>
  )
}

/**
 * The empty state for an aggregate viewer, and the one distinction it must not
 * lose.
 *
 * These viewers list a subset of what they load — the rows carrying a given
 * `subtype`, the messages that parsed into a day. When records came back and
 * none of them qualified, "No contacts were parsed for this case" is a claim
 * about the address book that the viewer is not entitled to make: what happened
 * is that rows arrived in a shape this viewer does not list. Say so, and keep
 * the plain empty state for the case where nothing was loaded at all.
 */
export function AggregateEmpty({
  title,
  body,
  loaded,
  listed,
  listedNoun,
}: {
  title: string
  body: string
  /** Records the load returned. */
  loaded: number
  /** Of those, how many this viewer would list. */
  listed: number
  /** What a listable record is called ("call row", "contact row"). */
  listedNoun: string
}) {
  return (
    <div>
      {loaded > 0 && listed === 0 && (
        <div className="warn-note" role="note">
          {formatCount(loaded)}{' '}
          {loaded === 1 ? 'record was' : 'records were'} loaded for this type,
          but none of them is a {listedNoun}, so none could be listed here. That
          is a statement about what the parser produced, not a finding that there
          were none.
        </div>
      )}
      <div className="empty-state">
        <h3>{title}</h3>
        <p>{body}</p>
      </div>
    </div>
  )
}
