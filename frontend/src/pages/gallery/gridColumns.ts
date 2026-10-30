/**
 * How many cells the responsive grid is currently laying out per row, measured
 * from the DOM rather than assumed: `.gl-grid` is `repeat(auto-fill, …)`, so the
 * answer depends on the window width, the sidebar and the zoom level.
 *
 * Cells on the same row share an `offsetTop`; count the run. Only elements
 * carrying `data-idx` are considered, so the windowing spacers and a list-view
 * header — which are children of the same container — cannot be counted as
 * cells and make the grid look one column wider than it is.
 *
 * Returns 1 when there is no layout to read (a list view, or an environment
 * without one), which is also the right answer for the single-column list.
 */
export function measureColumns(container: HTMLElement | null): number {
  const cells = container?.querySelectorAll<HTMLElement>('[data-idx]')
  if (!cells || cells.length < 2) return 1
  const top = cells[0].offsetTop
  let cols = 1
  for (let i = 1; i < cells.length; i += 1) {
    if (cells[i].offsetTop !== top) break
    cols += 1
  }
  return cols
}
