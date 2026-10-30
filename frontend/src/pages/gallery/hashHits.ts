import { apiFetch } from '../../api/http'
import type { HashSetInfo } from '../../api/types'

export interface HashHit {
  artifact_id: string
  hash_set_id: string
  hash_set_name: string
}

interface HashHitsResponse {
  hits: HashHit[]
  total: number
}

/** The endpoint clamps page_size to FILES_MAX_PAGE_SIZE, so request that. */
const HASH_HITS_PAGE_SIZE = 500
/** Bound the total hits pulled in for badge/filter indexing. */
const HASH_HITS_CAP = 50000

export interface HashHitsResult {
  hits: HashHit[]
  /** Total hits the case actually has (may exceed `hits.length`). */
  total: number
  /** True when the cap stopped us short of `total`, so badges/filtering under-report. */
  truncated: boolean
}

/**
 * Case-wide hash hits. Pages through every hit (bounded by HASH_HITS_CAP) so
 * matches past the first page still get their triage badges and filters, rather
 * than silently dropping everything beyond a single page. When the cap is hit
 * `truncated` is set so the caller can warn that badges/filtering under-report.
 *
 * What the examiner learns from `truncated`: whether a picture with no notable
 * badge was checked against the hash sets and did not match, or was never
 * reached. Those two render identically in the grid, so the cap has to be able
 * to say it bit WITHOUT depending on the server having sent a usable `total` —
 * deciding truncation from `total` alone means a response that omits the count
 * reports a capped result as complete, which is the silent cap this flag
 * exists to prevent.
 *
 * `cap` is the ceiling on hits held; it is a parameter only so the cap-hit path
 * can be exercised without serving fifty thousand rows, exactly as
 * `collectImageIds` does in the sibling module. Callers use the default.
 */
export const getHashHits = async (
  caseId: string,
  cap = HASH_HITS_CAP,
): Promise<HashHitsResult> => {
  const out: HashHit[] = []
  let total = 0
  let cappedShort = false
  for (let page = 1; ; page += 1) {
    const resp = await apiFetch<HashHitsResponse>(
      `/cases/${caseId}/hash_hits`,
      { query: { page, page_size: HASH_HITS_PAGE_SIZE } },
    )
    if (typeof resp.total === 'number') total = Math.max(total, resp.total)
    out.push(...resp.hits)
    // A short page is the server saying there is nothing after it. Stopping on
    // `total` alone means a response without a usable count walks all the way
    // to the cap; `total` then only decides whether the result is complete.
    if (resp.hits.length < HASH_HITS_PAGE_SIZE) break
    if (total > 0 && out.length >= total) break
    if (out.length >= cap) {
      // The server still had a full page for us and we ran out of budget: the
      // walk ended on OUR cap, which is truncation whatever `total` says.
      cappedShort = true
      break
    }
  }
  const hits = out.slice(0, cap)
  return {
    hits,
    total: Math.max(total, hits.length),
    truncated: cappedShort || hits.length < total,
  }
}

export interface HashFlag {
  /** True when the match is against a notable (known-bad / contraband) set. */
  notable: boolean
  setName: string
}

/**
 * Index artifact id -> hash-hit flag. An artifact matching several sets is
 * classified notable if any match is notable (contraband wins over known-good),
 * so triage never under-reports a hit.
 */
export function buildHashHitIndex(
  hits: HashHit[],
  sets: HashSetInfo[],
): Map<string, HashFlag> {
  const setType = new Map(sets.map((s) => [s.id, s.set_type]))
  const index = new Map<string, HashFlag>()
  for (const h of hits) {
    const notable = setType.get(h.hash_set_id) === 'notable'
    const existing = index.get(h.artifact_id)
    if (!existing || (notable && !existing.notable)) {
      index.set(h.artifact_id, { notable, setName: h.hash_set_name })
    }
  }
  return index
}
