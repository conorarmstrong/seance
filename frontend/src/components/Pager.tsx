import { ChevronsLeft, ChevronLeft, ChevronRight, ChevronsRight } from 'lucide-react'
import { formatCount } from '../lib/format'

/**
 * The pager under a paged table: where you are, how much there is, and the
 * controls to move.
 *
 * `totalCount` is the size of the set being paged, and the pager is the place
 * an examiner reads it from — it sits directly under the last row, closer to
 * hand than the count bar above the table. That makes an unqualified number
 * here load-bearing: some listings can only report a LOWER BOUND on their
 * population (a filter scan that stopped at its row ceiling, more matches than
 * the grid will list, rows the scan read and could not evaluate), and "1,234
 * rows" under those is a population claim nobody established.
 *
 * `totalIsFloor` is how the caller says so, and it is deliberately a boolean
 * the caller already holds rather than anything this component works out for
 * itself. The screens that can be short already decide it once — the file
 * grid's count bar reads `filter.inventory_incomplete` off the population
 * disclosure the server returned — and that same value is what belongs here.
 * Two components deciding independently whether a number is exact is how they
 * end up disagreeing in front of a witness, which is worse than either of them
 * being vague.
 *
 * It defaults to false, and callers whose count is always exact leave it off:
 * an "at least" on a number the server counted exactly is its own dishonesty,
 * because it makes an examiner hedge a figure that did not need hedging.
 *
 * When the count is a floor, two further things on this bar stop being true and
 * are handled the same way {@link ../pages/search/HitsPager HitsPager} handles
 * them:
 *
 * - the page total is that count divided by the page size, so it is a floor
 *   too, and it says so rather than stating "of 5" as a fact;
 * - the jump to the "last" page is withheld, because the page it would land on
 *   is not one the server ever claimed was the end. First, Prev and Next stay:
 *   page 1 is page 1 whatever the total turns out to be, and stepping one page
 *   at a time only ever visits pages the stated total already covers.
 */
export function Pager({
  page,
  totalPages,
  onPage,
  totalCount,
  totalIsFloor = false,
}: {
  page: number
  totalPages: number
  onPage: (page: number) => void
  /** Rows in the whole set. Omitted when the caller has no count to state. */
  totalCount?: number
  /**
   * True when `totalCount` is a lower bound rather than a total. Pass the same
   * value the surrounding screen's count uses; never a second computation of
   * it.
   */
  totalIsFloor?: boolean
}) {
  const atLeast = totalIsFloor ? 'at least ' : ''
  return (
    <div className="pager">
      <button className="btn btn-icon" disabled={page <= 1} onClick={() => onPage(1)} aria-label="First page">
        <ChevronsLeft size={15} />
      </button>
      <button
        className="btn"
        disabled={page <= 1}
        onClick={() => onPage(page - 1)}
      >
        <ChevronLeft size={15} /> Prev
      </button>
      <span data-testid="pager-status">
        Page {page} of {atLeast}
        {Math.max(totalPages, 1)}
        {totalCount != null && ` · ${atLeast}${formatCount(totalCount)} rows`}
      </span>
      <button
        className="btn"
        disabled={page >= totalPages}
        onClick={() => onPage(page + 1)}
      >
        Next <ChevronRight size={15} />
      </button>
      {!totalIsFloor && (
        <button
          className="btn btn-icon"
          disabled={page >= totalPages}
          onClick={() => onPage(totalPages)}
          aria-label="Last page"
        >
          <ChevronsRight size={15} />
        </button>
      )}
    </div>
  )
}
