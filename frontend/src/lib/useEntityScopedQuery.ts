import { useQuery, keepPreviousData } from '@tanstack/react-query'
import type { QueryFunctionContext, UseQueryOptions } from '@tanstack/react-query'

/**
 * A query whose cached/placeholder data is only shown when it belongs to the
 * entity currently on screen.
 *
 * The recurring defect this exists to eliminate: a page uses
 * `placeholderData: keepPreviousData` so paging feels smooth, but the same
 * placeholder is also shown when the *entity* changes (case, source, artifact,
 * folder, filter). The previous entity's rows then render under the new
 * entity's heading until the refetch resolves. In a forensics tool that is
 * evidence misattribution: case A's timeline under case B's name, artifact A's
 * bytes under artifact B's title, the previous folder's files under a new
 * breadcrumb. It produced BUG-068, 111, 112, 195, 196 and 198 in separate pages,
 * each fixed by hand-rolling the same gate.
 *
 * `scopeKey` is whatever identifies "the thing being looked at" — usually
 * `JSON.stringify({ caseId, sourceId, ...filters })`. Keep values that should
 * NOT blank the view (e.g. `page`) out of it, so pagination stays smooth.
 *
 * Returns the normal query result plus:
 *  - `stale`  — true when the data in hand belongs to a previous scope. Render a
 *               skeleton/empty state, never the rows.
 *  - `data`   — the underlying data (may be the previous scope's; gate on `stale`).
 *  - `scoped` — the data ONLY when it matches the current scope, else undefined.
 *               Prefer this: it makes the correct behaviour the default.
 */
export function useEntityScopedQuery<T>(
  scopeKey: string,
  options: Omit<UseQueryOptions<T>, 'placeholderData' | 'select'> & {
    queryKey: readonly unknown[]
  },
) {
  const inner = options.queryFn
  const query = useQuery<{ __scope: string; value: T }>({
    ...options,
    // Tag the response with the scope IN EFFECT WHEN IT WAS FETCHED. This must
    // happen in queryFn, not in `select`: `select` is re-applied to whatever
    // data is handed back — including the previous scope's placeholder — using
    // the CURRENT scopeKey, so the tag would always match and `stale` would
    // always be false. Tagging at fetch time is what makes a carried-over
    // placeholder identifiable at all.
    queryFn: async (ctx: QueryFunctionContext) => {
      const fetchedFor = scopeKey
      const fetch = inner as (c: QueryFunctionContext) => Promise<T> | T
      return { __scope: fetchedFor, value: await fetch(ctx) }
    },
    placeholderData: keepPreviousData,
  } as never)

  const tagged = query.data as { __scope: string; value: T } | undefined
  const stale = tagged != null && tagged.__scope !== scopeKey

  return {
    ...query,
    data: tagged?.value,
    /** Data for the CURRENT scope only — undefined while a switch is in flight. */
    scoped: stale ? undefined : tagged?.value,
    stale,
  }
}
