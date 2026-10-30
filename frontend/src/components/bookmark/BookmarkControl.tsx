import { useEffect, useId, useRef, useState } from 'react'
import {
  BookmarksProvider,
  useBookmarkApi,
  useIsBookmarked,
  useMarkedStore,
} from './BookmarksProvider'
import './bookmark.css'

/**
 * Capture a finding where it is found, with the reason attached.
 *
 * The control this replaces was a bare toggle: it stored `{ artifact_id }` and
 * nothing else, even though the endpoint has always taken a category and a
 * note. To record WHY a file mattered an examiner had to leave the evidence,
 * open the Bookmarks page, find the row in a flat list ordered by last edit,
 * click Edit, type, save and navigate back — seven steps away from the thing
 * they were looking at. Under time pressure that note is never written, and the
 * court record degrades to a list of unexplained stars.
 *
 * So the control opens a small form anchored to itself: category, and a note
 * box that takes focus immediately. The fast path is preserved exactly — open,
 * Enter, done, one plain bookmark — while the slow path is one keystroke away
 * from it rather than one page away.
 *
 * Escape dismisses without writing anything. The obvious alternative (Escape
 * saves a plain bookmark) was rejected: this is an evidential record, and a
 * keystroke that ordinarily means "cancel" must not create one, least of all
 * out of half-typed reasoning the examiner was in the middle of rejecting.
 */
export function BookmarkControl(props: {
  caseId: string
  artifactId: string
  /** What is being bookmarked, named in the control's accessible label. */
  subject: string
  className?: string
}) {
  // A control with no provider above it supplies its own, so a single control
  // on an artifact page still works exactly as it always did. A TABLE of them
  // must be wrapped once by the caller — see `BookmarksProvider` for what the
  // per-row cost of not doing so is.
  const store = useMarkedStore(props.caseId)
  if (!store) {
    return (
      <BookmarksProvider caseId={props.caseId}>
        <BookmarkControl {...props} />
      </BookmarksProvider>
    )
  }
  return <Control {...props} store={store} />
}

function Control({
  caseId,
  artifactId,
  subject,
  className,
  store,
}: {
  caseId: string
  artifactId: string
  subject: string
  className?: string
  store: NonNullable<ReturnType<typeof useMarkedStore>>
}) {
  const [open, setOpen] = useState(false)
  const wrapRef = useRef<HTMLSpanElement | null>(null)
  const starRef = useRef<HTMLButtonElement | null>(null)

  // Closing the form returns focus to the control that opened it. Without this
  // a keyboard examiner who presses Escape is left with focus on a detached
  // node, and the next Tab restarts from the top of the document — which on a
  // five-hundred-row table means losing their place in the evidence.
  const close = () => {
    setOpen(false)
    starRef.current?.focus()
  }

  // Only this row's answer, so a capture made on another row does not repaint
  // this one.
  const marked = useIsBookmarked(store, artifactId)

  // Dismiss on a click elsewhere. Registered only while open so the document
  // carries no listener for the hundreds of these a table renders.
  useEffect(() => {
    if (!open) return
    const onDown = (event: MouseEvent) => {
      if (!wrapRef.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const label =
    marked == null
      ? `Bookmark state unknown for ${subject}`
      : marked
        ? `Edit bookmark for ${subject}`
        : `Bookmark ${subject}`

  return (
    <span className={className ? `bmk ${className}` : 'bmk'} ref={wrapRef}>
      <button
        type="button"
        ref={starRef}
        className={marked ? 'bmk-star marked' : 'bmk-star'}
        aria-label={label}
        title={
          marked == null
            ? 'Whether this is bookmarked could not be determined — the bookmark list did not load.'
            : label
        }
        // A state that could not be loaded is not a state that can be toggled:
        // opening the form here would offer "Save bookmark" over a record that
        // may already have a note, and saving would overwrite it unseen.
        disabled={marked == null}
        aria-pressed={marked === true}
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        {marked ? '★' : '☆'}
      </button>
      {open && (
        <CapturePopover
          caseId={caseId}
          artifactId={artifactId}
          subject={subject}
          alreadyMarked={marked === true}
          onDone={close}
          onCancel={close}
        />
      )}
    </span>
  )
}

function CapturePopover({
  caseId,
  artifactId,
  subject,
  alreadyMarked,
  onDone,
  onCancel,
}: {
  caseId: string
  artifactId: string
  subject: string
  alreadyMarked: boolean
  onDone: () => void
  onCancel: () => void
}) {
  // The form is the only thing that needs the categories, the writes and the
  // in-flight state, and only one of them is ever open — so it is the only
  // thing that reads the context those changes wake.
  const bookmarks = useBookmarkApi()
  const noteId = useId()
  const categoryId = useId()
  const [note, setNote] = useState('')
  const [category, setCategory] = useState('')
  // An existing bookmark's stored values have to be in hand before the form may
  // be saved, or an edit blanks a note this control never displayed.
  const [loaded, setLoaded] = useState(!alreadyMarked)
  const [loadError, setLoadError] = useState<string | null>(null)
  const noteRef = useRef<HTMLTextAreaElement | null>(null)

  useEffect(() => {
    noteRef.current?.focus()
  }, [])

  useEffect(() => {
    if (!alreadyMarked) return
    let cancelled = false
    bookmarks
      .fetchOne(artifactId)
      .then((stored) => {
        if (cancelled) return
        setNote(stored.note ?? '')
        setCategory(stored.category_id ?? '')
        setLoaded(true)
      })
      .catch((error: Error) => {
        if (cancelled) return
        setLoadError(error.message)
      })
    return () => {
      cancelled = true
    }
    // `bookmarks` is rebuilt every render; the read is keyed by the two values
    // that actually identify it.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId, artifactId, alreadyMarked])

  const save = () => {
    if (!loaded) return
    const draft = { categoryId: category || undefined, note }
    const write = alreadyMarked
      ? bookmarks.update(artifactId, draft)
      : bookmarks.add(artifactId, draft)
    // Only a write that succeeded closes the form. A failure keeps the note on
    // screen — retypable, and visibly not recorded — rather than dismissing the
    // popover over an error the examiner would have to notice elsewhere.
    void write.then(onDone).catch(() => {})
  }

  return (
    <div
      className="bmk-pop"
      role="dialog"
      aria-label={`Bookmark ${subject}`}
      onKeyDown={(event) => {
        if (event.key === 'Escape') {
          event.stopPropagation()
          onCancel()
        }
      }}
    >
      <div className="bmk-pop-subject">{subject}</div>
      {bookmarks.lastError && (
        <p className="error-note" role="alert">
          This bookmark was NOT saved ({bookmarks.lastError}). Nothing has been
          recorded; the note above is still only on this screen.
        </p>
      )}
      {loadError && (
        <p className="error-note" role="alert">
          The stored bookmark could not be read ({loadError}), so it cannot be
          edited here without risking overwriting a note nobody has seen. Open
          the Bookmarks page to edit it.
        </p>
      )}
      <div className="bmk-pop-row">
        <label htmlFor={categoryId}>Category</label>
        <select
          id={categoryId}
          className="select"
          value={category}
          onChange={(event) => setCategory(event.target.value)}
        >
          <option value="">Uncategorized</option>
          {bookmarks.categories.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
            </option>
          ))}
        </select>
      </div>
      <div className="bmk-pop-row">
        <label htmlFor={noteId}>Note — why this matters</label>
        <textarea
          id={noteId}
          ref={noteRef}
          className="input bmk-pop-note"
          rows={3}
          value={note}
          placeholder="Why does this matter? Reaches the report."
          onChange={(event) => setNote(event.target.value)}
          onKeyDown={(event) => {
            // Enter saves so a capture is open-type-Enter; Shift+Enter is the
            // newline, because a note long enough to need paragraphs is a note
            // the examiner is not in a hurry over.
            if (event.key === 'Enter' && !event.shiftKey) {
              event.preventDefault()
              save()
            }
          }}
        />
      </div>
      <p className="bmk-pop-hint">
        The note and category are stored with the bookmark and printed in the
        report's findings section.
      </p>
      <div className="bmk-pop-actions">
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
        <button
          type="button"
          className="btn btn-primary"
          disabled={!loaded || bookmarks.busy}
          onClick={save}
        >
          Save bookmark
        </button>
      </div>
    </div>
  )
}
