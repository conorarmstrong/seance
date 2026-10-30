import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { KeyboardEvent, MouseEvent } from 'react'

/**
 * How long a type-ahead stays open. Long enough to type "sys32" as one search,
 * short enough that a pause means "start a new one". One window for every tree
 * in the product, because an examiner moves between them.
 */
const TYPEAHEAD_WINDOW_MS = 700

/** What the keys need to know about the row they were pressed on. */
export interface TreeKeyNode {
  /** Stable identity for the row; also written to `data-node-id`. */
  id: string
  /** Whether this row can hold children at all. */
  expandable: boolean
  /** Whether it is showing them now. */
  expanded: boolean
  /**
   * What Enter does on a row with no children of its own. Defaults to clicking
   * the row's label, which is where a mouse click goes.
   *
   * It is per row rather than per tree because only the row knows what it is:
   * the file system tree opens a FILE from Enter and toggles a FOLDER, and the
   * one place both facts are in scope is where the row is rendered.
   */
  activate?: () => void
  /**
   * What Space does on this row, branch or leaf. Defaults to the same
   * activation Enter uses.
   *
   * A tree that offers a preview separates the two: in the file system tree
   * Space fills the detail pane and Enter commits to opening the artifact, so
   * an examiner can walk a folder reading files without leaving the tree.
   */
  preview?: () => void
}

/** Props to spread onto a row's `<li>`. */
export interface TreeRowProps {
  role: 'treeitem'
  tabIndex: number
  'data-node-id': string
  'aria-expanded': boolean | undefined
  onKeyDown: (event: KeyboardEvent<HTMLElement>) => void
  onMouseDown: (event: MouseEvent<HTMLElement>) => void
}

export interface TreeKeyboard {
  /** Put on the root `<ul role="tree">`. */
  treeRef: React.RefObject<HTMLUListElement | null>
  rowProps: (node: TreeKeyNode) => TreeRowProps
}

/**
 * The WAI-ARIA tree keyboard contract, for every tree in the product: the two
 * navigator trees, the file system tree and the folder sidebar beside the file
 * grid. It was written twice before this — once here and once inside
 * `pages/files/FileTree` — and two implementations of one contract is where a
 * key quietly stops behaving the same in the tree an examiner happens to be in.
 *
 * Up/Down move between visible rows, Right opens a closed node and then steps
 * into it, Left closes an open one and otherwise steps out to the parent,
 * Home/End jump to the ends, Enter and Space activate the row's own label, and
 * a printable character type-aheads over the visible labels.
 *
 * Two problems are solved by the same mechanism. The first is that these trees
 * announced no tree semantics at all, so nothing about them was navigable by
 * keyboard: a screen-reader user heard a list of buttons and links, and a
 * sighted keyboard user paid two Tab presses per node — one for the caret, one
 * for the label — roughly forty presses to reach a hive six levels down. With
 * the row as the single roving tab stop, the whole tree costs one press and
 * the caret and label stop being stops at all (they stay clickable).
 *
 * The second is that the movement keys have to act on rows other than the one
 * that was pressed — Right stepping into a child, Left onto a parent — and
 * these trees fetch each level on demand, so there is no model of the tree in
 * JavaScript to walk. The row order the examiner sees IS the document order of
 * the rendered `treeitem`s, so that is what this walks: only rendered rows are
 * ever visited, which keeps every key proportional to what is on screen rather
 * than to the size of the evidence.
 *
 * The caller owns expansion (it has to: the state must outlive a node
 * unmounting) and is told about it through `setExpanded`. Activation defaults
 * to clicking the row's own label, so Enter goes exactly where a click on the
 * label goes and no destination is ever duplicated here; a row that needs
 * something else says so per row, through `activate` and `preview`.
 */
export function useTreeKeyboard({
  setExpanded,
  labelSelector = '.tree-label',
}: {
  setExpanded: (id: string, expanded: boolean) => void
  /**
   * What a row's own label is, for type-ahead and for default activation.
   *
   * The navigator trees mark theirs `.tree-label`; the file system tree names
   * its rows with `.ft-name` and the folder sidebar with `.fg-tree-label`.
   * Every one of them puts the label BEFORE the `role="group"` holding its
   * children, so `querySelector` from the row finds the row's own label and
   * not a descendant's.
   */
  labelSelector?: string
}): TreeKeyboard {
  const treeRef = useRef<HTMLUListElement>(null)
  const [activeId, setActiveId] = useState<string | null>(null)
  const typeahead = useRef({ buffer: '', at: 0 })

  const rows = useCallback((): HTMLElement[] => {
    const root = treeRef.current
    if (!root) return []
    return Array.from(root.querySelectorAll<HTMLElement>('[role="treeitem"]'))
  }, [])

  const focusRow = useCallback((el: HTMLElement | null | undefined) => {
    if (!el) return
    setActiveId(el.dataset.nodeId ?? null)
    el.focus()
    // A tree expanded a few levels is taller than the sidebar, so the row just
    // moved to is routinely below the fold; `nearest` scrolls only as far as
    // it must.
    el.scrollIntoView?.({ block: 'nearest' })
  }, [])

  // Whenever the rendered rows change — a level arrives, a subtree collapses
  // out from under the active row — make sure exactly one row is still in the
  // tab order. Without this the tree can end up with none, and Tab skips it
  // entirely.
  useEffect(() => {
    const root = treeRef.current
    if (!root) return
    if (root.querySelector('[role="treeitem"][tabindex="0"]')) return
    const first = root.querySelector<HTMLElement>('[role="treeitem"]')
    if (first?.dataset.nodeId) setActiveId(first.dataset.nodeId)
  })

  return useMemo<TreeKeyboard>(() => {
    const jumpBy = (from: HTMLElement, delta: number) => {
      const all = rows()
      const index = all.indexOf(from)
      if (index === -1) return
      focusRow(all[Math.min(all.length - 1, Math.max(0, index + delta))])
    }

    const typeAhead = (from: HTMLElement, char: string) => {
      const now = Date.now()
      const state = typeahead.current
      state.buffer =
        now - state.at > TYPEAHEAD_WINDOW_MS ? char : state.buffer + char
      state.at = now
      const all = rows()
      const start = all.indexOf(from)
      // Search forward from the row after this one and wrap, so pressing the
      // same letter repeatedly walks the matches rather than sticking. A
      // buffer that matches nothing moves nothing: jumping to whatever the
      // last letter alone matched would land the examiner on a node they did
      // not name.
      for (let step = 1; step <= all.length; step += 1) {
        const candidate = all[(start + step) % all.length]
        const label = candidate
          .querySelector(labelSelector)
          ?.textContent?.toLowerCase()
        if (label?.startsWith(state.buffer)) {
          focusRow(candidate)
          return
        }
      }
    }

    const openRow = (row: HTMLElement) => {
      // The label is a Link in the sidebar and a button in the workbench, and
      // clicking it is what a mouse does. Going through the element rather
      // than rebuilding its destination here means the keyboard can never
      // arrive somewhere the mouse would not.
      row.querySelector<HTMLElement>(labelSelector)?.click()
    }

    return {
      treeRef,
      rowProps: (node: TreeKeyNode): TreeRowProps => ({
        role: 'treeitem',
        tabIndex: node.id === activeId ? 0 : -1,
        'data-node-id': node.id,
        'aria-expanded': node.expandable ? node.expanded : undefined,
        // Pointer-down rather than click, so that the row the keyboard
        // continues from is the row the examiner is looking at even when the
        // click landed on a control that stops the click event.
        //
        // Rows nest, so a press inside a child also bubbles through every
        // ancestor row, and the LAST handler to run would win: clicking a file
        // six levels down would leave the tab stop sitting on a root folder.
        // Only the innermost row the press actually landed in claims it.
        onMouseDown: (event: MouseEvent<HTMLElement>) => {
          const target = event.target as HTMLElement | null
          if (target?.closest?.('[role="treeitem"]') !== event.currentTarget) {
            return
          }
          setActiveId(node.id)
        },
        onKeyDown: (event: KeyboardEvent<HTMLElement>) => {
          const row = event.currentTarget
          // Rows nest, so without stopping propagation a keypress on a leaf
          // would be handled again by every ancestor row on the way up. It is
          // claimed per key rather than for the whole handler, because
          // stopping every key also stops it reaching the window where ⌘K and
          // the other global shortcuts listen — which would cost the examiner
          // the command palette for as long as their focus was in the tree.
          const take = () => {
            event.preventDefault()
            event.stopPropagation()
          }

          switch (event.key) {
            case 'ArrowDown':
              take()
              jumpBy(row, 1)
              return
            case 'ArrowUp':
              take()
              jumpBy(row, -1)
              return
            case 'Home':
              take()
              focusRow(rows()[0])
              return
            case 'End': {
              take()
              const all = rows()
              focusRow(all[all.length - 1])
              return
            }
            case 'ArrowRight':
              take()
              if (!node.expandable) return
              if (!node.expanded) {
                // Open it and stay put: the examiner asked to see inside, not
                // to move. A second Right steps in.
                setExpanded(node.id, true)
                return
              }
              focusRow(
                row.querySelector<HTMLElement>(
                  '[role="group"] [role="treeitem"]',
                ),
              )
              return
            case 'ArrowLeft':
              take()
              if (node.expandable && node.expanded) {
                setExpanded(node.id, false)
                return
              }
              focusRow(row.parentElement?.closest<HTMLElement>('[role="treeitem"]'))
              return
            case 'Enter':
              take()
              if (node.expandable) setExpanded(node.id, !node.expanded)
              else if (node.activate) node.activate()
              else openRow(row)
              return
            case ' ':
              // Space opens whatever the row offers, including for a node that
              // also has children — the difference from Enter is that Enter on
              // a parent is about seeing inside it. A row that offers a preview
              // instead says so. It must swallow the key either way, or the
              // pane scrolls a page down under them.
              take()
              if (node.preview) node.preview()
              else openRow(row)
              return
          }

          if (
            event.key.length === 1 &&
            !event.ctrlKey &&
            !event.metaKey &&
            !event.altKey
          ) {
            take()
            typeAhead(row, event.key.toLowerCase())
          }
        },
      }),
    }
  }, [activeId, focusRow, labelSelector, rows, setExpanded])
}
