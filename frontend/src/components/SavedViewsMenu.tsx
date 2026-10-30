import { useEffect, useMemo, useRef, useState } from 'react'
import { Star, X } from 'lucide-react'
import './saved-views.css'

interface SavedView {
  name: string
  query: string
}

function load(key: string): SavedView[] {
  try {
    const raw = localStorage.getItem(key)
    if (raw) {
      const v = JSON.parse(raw)
      if (Array.isArray(v)) return v as SavedView[]
    }
  } catch {
    // corrupt entry — start fresh
  }
  return []
}

function persist(key: string, views: SavedView[]) {
  try {
    localStorage.setItem(key, JSON.stringify(views))
  } catch {
    // storage unavailable — degrade to session-only
  }
}

/**
 * Named filter presets ("saved views"). Captures the current URL query string
 * under a name and restores it later, per case + page. Backed by localStorage.
 */
export function SavedViewsMenu({
  storageKey,
  currentQuery,
  onApply,
}: {
  storageKey: string
  currentQuery: string
  onApply: (query: string) => void
}) {
  // `storageKey` carries the case (`seance.views.timeline.<caseId>`), and the
  // pages that host this menu stay mounted when `:caseId` changes. Loading the
  // list once at mount left case A's views listed under case B, applying case
  // A's filter query to case B's table, and — because `persist` writes to the
  // CURRENT key — the next save copied case A's whole view list into case B's
  // localStorage entry. The list is now derived from the key in hand, with the
  // held copy only readable while it still belongs to that key, so a view list
  // can never outlive its case (B2-017).
  const stored = useMemo(() => load(storageKey), [storageKey])
  const [held, setHeld] = useState<{ key: string; views: SavedView[] } | null>(
    null,
  )
  const views = held && held.key === storageKey ? held.views : stored
  const setViews = (next: SavedView[]) => setHeld({ key: storageKey, views: next })
  const [openFor, setOpenFor] = useState<string | null>(null)
  const open = openFor === storageKey
  const setOpen = (next: boolean | ((previous: boolean) => boolean)) =>
    setOpenFor((previous) => {
      const wasOpen = previous === storageKey
      const willOpen = typeof next === 'function' ? next(wasOpen) : next
      return willOpen ? storageKey : null
    })
  const [nameState, setNameState] = useState<{ key: string; value: string }>({
    key: storageKey,
    value: '',
  })
  const name = nameState.key === storageKey ? nameState.value : ''
  const setName = (value: string) => setNameState({ key: storageKey, value })
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpenFor(null)
      }
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])

  const save = () => {
    const n = name.trim()
    if (!n) return
    const next = [...views.filter((v) => v.name !== n), { name: n, query: currentQuery }].sort(
      (a, b) => a.name.localeCompare(b.name),
    )
    setViews(next)
    persist(storageKey, next)
    setName('')
  }
  const remove = (n: string) => {
    const next = views.filter((v) => v.name !== n)
    setViews(next)
    persist(storageKey, next)
  }

  return (
    <div className="sv" ref={ref}>
      <button
        className="btn sv-btn"
        aria-expanded={open}
        aria-haspopup="menu"
        onClick={() => setOpen((o) => !o)}
      >
        <Star size={13} /> Views{views.length ? ` · ${views.length}` : ''}
      </button>
      {open && (
        <div className="sv-menu" role="menu">
          <div className="sv-head">Saved views</div>
          {views.length === 0 && (
            <div className="sv-empty">No saved views yet</div>
          )}
          {views.map((v) => (
            <div className="sv-item" key={v.name}>
              <button
                className="sv-apply"
                onClick={() => {
                  onApply(v.query)
                  setOpen(false)
                }}
              >
                {v.name}
              </button>
              <button
                className="sv-del"
                aria-label={`Delete view ${v.name}`}
                onClick={() => remove(v.name)}
              >
                <X size={13} />
              </button>
            </div>
          ))}
          <div className="sv-save">
            <input
              className="input sv-input"
              placeholder="Name this view…"
              aria-label="View name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') save()
              }}
            />
            <button
              className="btn sv-save-btn"
              disabled={!name.trim()}
              onClick={save}
            >
              Save
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
