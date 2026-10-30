import { ChevronsLeft, ChevronLeft, ChevronRight, ChevronsRight } from 'lucide-react'
import { formatCount } from '../../lib/format'

/**
 * The pager for a page of search hits.
 *
 * This is deliberately NOT `components/Pager`. That component states "Page 3 of
 * 341" as a fact and always offers a jump to the last page, and both of those
 * are claims a search result set frequently cannot support: when the server
 * could not count past its scan budget, `total_count` is a floor, so the number
 * of pages is a floor too and the "last" page is not the last one. A control
 * that jumps to a page it calls the end, on a match count that is only a
 * minimum, is exactly the kind of confident-looking wrong answer that gets
 * quoted under oath.
 *
 * So: the page total is rendered as "of at least N" when the count is a floor,
 * and the LAST-page jump is withheld in that case rather than pointed at a page
 * the server never claimed was final.
 *
 * Only that one. The jump to page 1 stays: page 1 is page 1 whatever the total
 * turns out to be, and withholding it would cost the examiner a control while
 * buying no honesty at all. Prev and Next stay too, because walking one page at
 * a time is sound whatever the total is — `hasNext` is decided by what the
 * server actually served, not by arithmetic against a number the server
 * explicitly refused to call a total.
 *
 * # The two ends of a deep result set
 *
 * Past the server's jump ceiling the walk continues by cursor, which resumes
 * from where the last page stopped instead of counting from the start. Forward
 * is therefore always available while the server keeps handing cursors back —
 * but BACKWARD is not: a cursor points one way, and the offset that would name
 * the previous page is past the ceiling the server enforces. So `prevReachable`
 * is passed in rather than derived from the page number, and a Prev that cannot
 * be served is disabled with a title that says why instead of being offered and
 * then refused. The jump to the last page is withheld on the same footing as it
 * is for a floored count: `lastJumpablePage` is the deepest page a jump can
 * land on, and calling it "last" when it is not would be the same confident
 * wrong answer.
 *
 * ## Why there is no back-stack of cursors
 *
 * The obvious way to give Prev back past the ceiling is to carry the cursors
 * already visited in the URL, so Prev replays a position the examiner has been
 * to. It was considered and rejected, and the reasons are recorded here because
 * the idea is obvious enough to be proposed again.
 *
 * 1. It duplicates a mechanism that already works and works better. Every
 *    position this screen visits — offset or cursor — is PUSHED onto the tab's
 *    history rather than replacing the entry (see `goToPage` in `SearchPage`).
 *    The browser's Back therefore already replays the exact pages walked, in
 *    the order they were read, and it is the control examiners reach for.
 *    A URL back-stack would be a second, divergent copy of the history stack,
 *    and two mechanisms for "where was I" is how they come to disagree.
 * 2. The URL cost is forensic, not cosmetic. These links are pasted into case
 *    notes, handover emails and exhibits (S3, S4). One opaque cursor already
 *    strains that; forty of them makes a link that wraps, truncates in mail
 *    clients, and gets quoted back missing a chunk — a shared position that
 *    silently resolves to a different page is exactly the failure this screen
 *    spends everything else avoiding.
 * 3. It scales with the walk, and the walk is the deep case (S5). Forty pages
 *    is a forty-entry stack, and every history entry holds its own copy, so the
 *    characters carried grow with the square of the pages read.
 * 4. It would not buy honesty. A replayed cursor is pinned to the snapshot it
 *    was minted against and must be refused exactly as any other once the index
 *    moves — so a back-stack Prev would fail in the one place the examiner is
 *    most certain it should work, under a label that promises a direction
 *    rather than a caveat. A control disabled up front, saying what it cannot
 *    do, survives cross-examination; one that works four times and then refuses
 *    does not.
 *
 * What the rejection owes the examiner is the route that DOES work, so the
 * disabled Prev names it: Back, conditionally, because someone who opened a
 * deep link from a handover has no earlier page of hits behind them and must
 * not be sent hunting for one. First page is the answer for them, and it is on
 * the same bar.
 *
 * The shared `.pager` class is reused so this reads identically to every other
 * pager in the product.
 */
export function HitsPager({
  page,
  totalPages,
  totalIsFloor,
  hasNext,
  prevReachable,
  lastJumpablePage,
  onPage,
  onNext,
}: {
  /** 1-based page number, derived from the offset the server SERVED. */
  page: number
  /** Pages the stated match count implies; a floor when `totalIsFloor`. */
  totalPages: number
  /** True when the match count behind `totalPages` is a lower bound. */
  totalIsFloor: boolean
  /** True when the server's answer shows there are further matches to fetch. */
  hasNext: boolean
  /** True when the page before this one can still be asked for. */
  prevReachable: boolean
  /**
   * The deepest page a jump can land on. Equal to `totalPages` until the
   * server's offset ceiling bites; past that, jumping stops here while walking
   * carries on.
   */
  lastJumpablePage: number
  onPage: (page: number) => void
  onNext: () => void
}) {
  // The end of the set is nameable only when the count is exact AND a jump can
  // actually land there. Either failing, the control would point at a page this
  // pager cannot honestly call the last one.
  const lastPageIsNameable = !totalIsFloor && lastJumpablePage >= totalPages
  return (
    <div className="pager srch-pager">
      <button
        type="button"
        className="btn btn-icon"
        disabled={page <= 1}
        onClick={() => onPage(1)}
        aria-label="First page"
      >
        <ChevronsLeft size={15} />
      </button>
      <button
        type="button"
        className="btn"
        disabled={!prevReachable}
        title={
          page > 1 && !prevReachable
            ? 'This page was reached by walking forward past the point the server will jump to, so the page before it cannot be asked for directly. If you walked here, your browser’s Back button returns to the pages you already read. Otherwise, go to the first page and walk again.'
            : undefined
        }
        onClick={() => onPage(page - 1)}
      >
        <ChevronLeft size={15} /> Prev
      </button>
      <span>
        Page {formatCount(page)} of {totalIsFloor ? 'at least ' : ''}
        {formatCount(Math.max(totalPages, 1))}
      </span>
      <button
        type="button"
        className="btn"
        disabled={!hasNext}
        onClick={onNext}
      >
        Next <ChevronRight size={15} />
      </button>
      {lastPageIsNameable && (
        <button
          type="button"
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
