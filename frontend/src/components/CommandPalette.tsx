import { useEffect, useMemo, useRef, useState } from 'react'
import './command-palette.css'

export interface Command {
  id: string
  label: string
  hint?: string
  /**
   * Words the examiner says for this command that its label does not contain —
   * "chats" for Communications, "gps" for Map. Matched alongside the label, and
   * the alias that matched is shown on the row so the examiner learns the name
   * the rest of the product uses.
   */
  keywords?: string[]
  run: () => void
}

/**
 * Score `label` against what the examiner typed, or return null when the label
 * does not match at all.
 *
 * Matching is a subsequence rather than a substring: an examiner reaching for
 * the timeline types "tml" or "time line" as often as "timeline", and a bare
 * `includes` answers all but the last of those with "No matches", which reads
 * as the palette being broken rather than as the query being loose.
 * Whitespace in the query is ignored for the same reason.
 *
 * The score exists to keep the obvious answer first: characters that land on a
 * word boundary or run consecutively are worth more than characters scavenged
 * from the middle of separate words, so "sea" puts "Go to Search" above a
 * label that merely happens to contain those letters in order.
 */
export function commandScore(label: string, query: string): number | null {
  const haystack = label.toLowerCase()
  const needle = query.toLowerCase().replace(/\s+/g, '')
  if (needle === '') return 0

  let score = 0
  let from = 0
  let previous = -2

  for (const char of needle) {
    const at = haystack.indexOf(char, from)
    if (at === -1) return null
    const startsWord = at === 0 || !/[a-z0-9]/.test(haystack[at - 1])
    if (startsWord) score += 10
    if (at === previous + 1) score += 5
    // Skipping a long way to find the next character is weak evidence, but
    // capped so that one late character cannot sink an otherwise good match.
    score -= Math.min(at - from, 10)
    previous = at
    from = at + 1
  }
  return score
}

/**
 * How much worse an alias match is than the same match on the command's label.
 *
 * Small on purpose. Its only job is to break the tie when the SAME command
 * matches both ways, so that a command whose own name answers the query is not
 * annotated with an alias that answers it no better.
 *
 * It must not be large, and it must not become a tier ("a label match always
 * wins"). Both were tried and both are wrong for the same reason: a query
 * scavenges letters out of unrelated labels surprisingly often — "gps" really
 * does appear in order inside "Go to Parsed Records" — and an exact alias hit
 * has to beat that. The ranking that matters is pinned in commands.test.ts
 * against the real destination list rather than guessed at here.
 */
const ALIAS_PENALTY = 4

/**
 * The best score any of a command's names gets against the query, plus the
 * alias that earned it (null when the label itself matched, or when nothing
 * did).
 *
 * Showing the winning alias matters: an examiner who types "whatsapp" and is
 * offered "Go to Communications" has been given an answer with no visible
 * connection to the question. Naming the alias on the row turns the same hit
 * into the thing they actually needed to learn — what this product calls the
 * view they were looking for.
 */
export function matchCommand(
  command: Command,
  query: string,
): { score: number; alias: string | null } | null {
  const onLabel = commandScore(command.label, query)
  let best = onLabel === null ? null : { score: onLabel, alias: null as string | null }

  for (const keyword of command.keywords ?? []) {
    const score = commandScore(keyword, query)
    if (score === null) continue
    const scored = score - ALIAS_PENALTY
    if (best === null || scored > best.score) best = { score: scored, alias: keyword }
  }
  return best
}

/**
 * The commands that match `query`, best first.
 *
 * Ties keep the order the caller supplied, which is the order of the nav rail,
 * so a query that says nothing about ranking still reads top-to-bottom the way
 * the sidebar does.
 *
 * Exported because the ranking is the palette's whole promise — that the word
 * an examiner says lands on the view they meant — and that promise is pinned
 * against the real destination list, not against invented labels.
 */
export function rankCommands(commands: Command[], query: string): Command[] {
  return commands
    .map((command, index) => ({ command, index, match: matchCommand(command, query) }))
    .filter((row) => row.match !== null)
    .sort(
      (a, b) =>
        (b.match as { score: number }).score - (a.match as { score: number }).score ||
        a.index - b.index,
    )
    .map((row) =>
      // A command's own hint (a real shortcut, say) outranks the alias: the
      // shortcut is durable information, the alias only explains this one query.
      row.match?.alias && !row.command.hint
        ? { ...row.command, hint: row.match.alias }
        : row.command,
    )
}

/**
 * Global ⌘K / Ctrl-K command palette: fuzzy-jump to any view and run quick
 * actions without leaving the keyboard. A fallback "Search evidence for …"
 * entry turns whatever you typed into a full-text search.
 *
 * This is the one feature whose whole purpose is to keep hands off the mouse,
 * so it keeps the listbox contract that implies: the active option is always
 * scrolled into view, it is named to assistive tech through
 * aria-activedescendant, and closing the palette puts focus back exactly where
 * it came from rather than dropping it on <body>.
 */
export function CommandPalette({
  commands,
  onSearch,
}: {
  commands: Command[]
  onSearch?: (query: string) => void
}) {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLUListElement>(null)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen((o) => !o)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => {
    if (!open) return
    // Whatever the examiner was on before ⌘K. Returning focus there on close
    // is what makes the palette free to open: without it, dismissing the
    // palette drops focus on <body> and the next Tab restarts at the top of
    // the page, costing exactly the position the palette was meant to keep.
    const opener = document.activeElement as HTMLElement | null
    setQ('')
    setSel(0)
    inputRef.current?.focus()
    return () => opener?.focus?.()
  }, [open])

  const items = useMemo(() => {
    const query = q.trim()
    const list: Command[] = query ? rankCommands(commands, query) : [...commands]
    if (query && onSearch) {
      list.push({
        id: '__search',
        label: `Search evidence for “${query}”`,
        hint: '↵',
        run: () => onSearch(query),
      })
    }
    return list
  }, [q, commands, onSearch])

  useEffect(() => {
    setSel((s) => Math.min(s, Math.max(0, items.length - 1)))
  }, [items])

  // The list is capped at 46vh, so past roughly the twelfth item the active
  // row leaves it and the examiner is arrowing blind. `nearest` scrolls only
  // as far as it must, so moving within the visible rows does not jolt.
  useEffect(() => {
    if (!open) return
    listRef.current
      ?.querySelector<HTMLElement>('[data-active="true"]')
      ?.scrollIntoView?.({ block: 'nearest' })
  }, [sel, open, items.length])

  if (!open) return null

  const close = () => setOpen(false)
  const exec = (i: number) => {
    const it = items[i]
    if (it) {
      close()
      it.run()
    }
  }
  const optionId = (i: number) => `cmdk-option-${i}`

  return (
    <div className="cmdk-overlay" onMouseDown={close}>
      <div
        className="cmdk"
        role="dialog"
        aria-label="Command palette"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <input
          ref={inputRef}
          className="cmdk-input"
          placeholder="Jump to a view, or search evidence…"
          value={q}
          aria-label="Command"
          role="combobox"
          aria-expanded="true"
          aria-controls="cmdk-list"
          aria-autocomplete="list"
          aria-activedescendant={items.length > 0 ? optionId(sel) : undefined}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              close()
            } else if (e.key === 'ArrowDown') {
              e.preventDefault()
              setSel((s) => Math.min(s + 1, items.length - 1))
            } else if (e.key === 'ArrowUp') {
              e.preventDefault()
              setSel((s) => Math.max(s - 1, 0))
            } else if (e.key === 'Enter') {
              e.preventDefault()
              exec(sel)
            }
          }}
        />
        <ul id="cmdk-list" ref={listRef} className="cmdk-list" role="listbox" aria-label="Commands">
          {items.length === 0 && (
            <li role="presentation" className="cmdk-empty">
              No matches
            </li>
          )}
          {items.map((it, i) => (
            <li
              key={it.id}
              id={optionId(i)}
              role="option"
              aria-selected={i === sel}
              data-active={i === sel ? 'true' : undefined}
              className={i === sel ? 'cmdk-item active' : 'cmdk-item'}
              onMouseEnter={() => setSel(i)}
              onClick={() => exec(i)}
            >
              <span className="cmdk-label">{it.label}</span>
              {it.hint && <span className="cmdk-hint mono">{it.hint}</span>}
            </li>
          ))}
        </ul>
        <div className="cmdk-foot mono">
          <span>↑↓ navigate</span>
          <span>↵ open</span>
          <span>esc close</span>
        </div>
      </div>
    </div>
  )
}
