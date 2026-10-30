import {
  useEffect,
  useRef,
  type CSSProperties,
  type KeyboardEvent as ReactKeyboardEvent,
} from 'react'
import { createPortal } from 'react-dom'
import './context-menu.css'

export interface ContextMenuItem {
  label: string
  onClick?: () => void
  disabled?: boolean
  danger?: boolean
  /** Small dimmed sub-label under the item. */
  note?: string
  /** Draw a divider after this item. */
  separatorAfter?: boolean
}

/**
 * Every item that can actually be chosen, in the order they are drawn.
 * Disabled items are left out: stopping the arrows on an item that does
 * nothing is a dead keypress in a list short enough that every press counts.
 */
function enabledItems(root: HTMLElement | null): HTMLButtonElement[] {
  return Array.from(
    root?.querySelectorAll<HTMLButtonElement>(
      '.ctx-menu-item:not([disabled])',
    ) ?? [],
  )
}

/**
 * Everything inside `root` that can take focus, in document order.
 *
 * Used only to find a landing place when the element that opened the menu no
 * longer exists to take focus back, so it is deliberately a plain document-order
 * query: no visibility filtering, because jsdom performs no layout and a filter
 * that reads `offsetParent` would behave differently in tests than in a browser.
 * `[hidden]` is honoured because it is a DOM fact rather than a computed one.
 */
function focusableWithin(root: HTMLElement): HTMLElement[] {
  return Array.from(
    root.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), input:not([disabled]), ' +
        'select:not([disabled]), textarea:not([disabled]), ' +
        '[tabindex]:not([tabindex="-1"])',
    ),
  ).filter((el) => !el.closest('[hidden]') && !el.closest('.ctx-menu'))
}

/**
 * Where focus goes when the opener has been unmounted by the very action the
 * menu triggered.
 *
 * The honest destination is the thing the examiner just chose. A menu names its
 * destinations, and for a caller that navigates, the chosen destination is
 * usually on screen afterwards under that same name — the breadcrumb overflow
 * is exactly this: choose "AppData" and a crumb button labelled "AppData"
 * appears in the path. So the nearest ancestor of the dead opener that is still
 * in the document is searched for a control carrying the chosen label, and
 * `aria-current` breaks the tie when a path repeats a folder name.
 *
 * Failing that, the first focusable control in that surviving region: the
 * examiner is at least left standing where they were rather than at the top of
 * the document. `document.body` and `<html>` are not regions — landing there is
 * the failure this exists to prevent — so the chain excludes them and the
 * caller keeps its no-op.
 *
 * `ancestors` has to have been captured while the opener was still in the
 * document. React detaches a removed subtree by unlinking its topmost removed
 * node, so once the opener is gone, walking up from it stops inside the
 * detached fragment and never reaches the region that survived.
 */
function landingPlace(
  ancestors: HTMLElement[],
  chosenLabel: string | null,
): HTMLElement | null {
  for (const region of ancestors) {
    if (!region.isConnected) continue
    const candidates = focusableWithin(region)
    if (candidates.length === 0) continue
    if (chosenLabel !== null) {
      const named = candidates.filter(
        (el) =>
          el.textContent?.trim() === chosenLabel ||
          el.getAttribute('aria-label') === chosenLabel,
      )
      const destination =
        named.find((el) => el.getAttribute('aria-current')) ?? named[0]
      if (destination) return destination
    }
    return candidates[0]
  }
  return null
}

/**
 * A lightweight right-click menu, portalled to <body> so it escapes any
 * overflow-clipped ancestor. Closes on outside click, Escape, or a selection.
 * There was no context-menu primitive in the codebase before this.
 *
 * It carries the menu keyboard contract that role="menu" promises: focus
 * enters on open, ArrowUp/ArrowDown roll over the choosable items, Home/End
 * jump to the ends, Escape closes, and focus returns to whatever opened it.
 */
export function ContextMenu({
  x,
  y,
  header,
  footer,
  items,
  onClose,
}: {
  x: number
  y: number
  header?: string
  footer?: string
  items: ContextMenuItem[]
  onClose: () => void
}) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose()
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('mousedown', onDown)
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('mousedown', onDown)
      window.removeEventListener('keydown', onKey)
    }
  }, [onClose])

  // The label of the item the examiner chose, if they chose one, so the close
  // handler can aim focus at the destination rather than at the control that
  // sent them there. A ref rather than state: it is read once during the
  // unmount cleanup and must never cause a render of a menu that is closing.
  const chosen = useRef<string | null>(null)

  // Take focus on open and give it back on close — the same contract Modal
  // keeps. The menu is portalled to <body>, so a menu that leaves focus on the
  // element that opened it announces itself to a screen reader as a menu while
  // no key can reach it: the arrows do nothing and Tab lands on whatever
  // follows the portal in document order, nowhere near the menu. Any action
  // offered only through the right-click menu would then be keyboard-dead.
  //
  // Giving focus back to the opener only works while the opener still exists.
  // Some callers unmount it with the very action the menu triggered — the
  // breadcrumb overflow draws its `…` control only while the path is long
  // enough to collapse, so choosing an ancestor folder shortens the path and
  // removes the control in the same commit that closes the menu. This cleanup
  // is a passive one, so it runs after that DOM change: `opener` is already
  // detached, `focus()` on it is a silent no-op, and focus falls to <body> —
  // which is the exact regression this effect exists to prevent. So when the
  // opener has not survived, focus goes where the examiner was going instead.
  //
  // The opener can also outlive this cleanup by one tick. When the caller's
  // action is a route change rather than a plain state change, the URL update
  // is committed in a LATER render than the one that closes the menu, so the
  // opener is still in the document here, takes focus, and is removed
  // immediately afterwards — focus lands on <body> just the same, and by then
  // there is no component left to notice. That is the real breadcrumb
  // sequence. So the hand-back is checked once more after the DOM has settled,
  // and only steps in if focus was actually dropped: wherever focus has
  // legitimately gone in the meantime is not ours to take back.
  useEffect(() => {
    const opener =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null
    const ancestors: HTMLElement[] = []
    for (
      let node = opener?.parentElement ?? null;
      node && node !== document.body && node !== document.documentElement;
      node = node.parentElement
    ) {
      ancestors.push(node)
    }
    enabledItems(ref.current)[0]?.focus()
    return () => {
      if (!opener) return
      if (opener.isConnected) opener.focus()
      else landingPlace(ancestors, chosen.current)?.focus()

      // Deferred by a task, because the deferred commit was already queued —
      // the caller dispatched it inside the click, before this cleanup ran —
      // and React's scheduler drains ahead of a timer. So the caller's
      // navigation has landed by the time this reads the DOM. One shot, and a
      // no-op in every case where the hand-back above held.
      setTimeout(() => {
        if (opener.isConnected) return
        const active = document.activeElement
        if (active !== null && active !== document.body) return
        landingPlace(ancestors, chosen.current)?.focus()
      }, 0)
    }
  }, [])

  // Keep the menu inside the viewport.
  const estHeight = 44 + items.length * 40 + (footer ? 28 : 0)
  const style: CSSProperties = {
    left: Math.max(8, Math.min(x, window.innerWidth - 250)),
    top: Math.max(8, Math.min(y, window.innerHeight - estHeight)),
  }

  // Roving the arrows over the item buttons. Wrapping rather than clamping:
  // a context menu is a short ring, and past the last item the next item is
  // the first one.
  function onKeyDown(event: ReactKeyboardEvent<HTMLDivElement>) {
    const buttons = enabledItems(ref.current)
    if (buttons.length === 0) return
    const index = buttons.indexOf(document.activeElement as HTMLButtonElement)
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault()
        buttons[(Math.max(index, -1) + 1) % buttons.length].focus()
        break
      case 'ArrowUp':
        event.preventDefault()
        buttons[(index <= 0 ? buttons.length : index) - 1].focus()
        break
      case 'Home':
        event.preventDefault()
        buttons[0].focus()
        break
      case 'End':
        event.preventDefault()
        buttons[buttons.length - 1].focus()
        break
    }
  }

  return createPortal(
    <div
      ref={ref}
      className="ctx-menu"
      style={style}
      role="menu"
      onKeyDown={onKeyDown}
    >
      {header && <div className="ctx-menu-header">{header}</div>}
      {items.map((item, i) => (
        <div key={i}>
          <button
            type="button"
            role="menuitem"
            className={`ctx-menu-item${item.danger ? ' danger' : ''}`}
            disabled={item.disabled}
            onClick={() => {
              // Recorded before the handler runs, because the handler is what
              // may destroy the opener and it is this label that then says
              // where the examiner meant to end up.
              chosen.current = item.label
              item.onClick?.()
              onClose()
            }}
          >
            <span className="ctx-menu-label">{item.label}</span>
            {item.note && <span className="ctx-menu-note">{item.note}</span>}
          </button>
          {item.separatorAfter && <div className="ctx-menu-sep" />}
        </div>
      ))}
      {footer && <div className="ctx-menu-footer">{footer}</div>}
    </div>,
    document.body,
  )
}
