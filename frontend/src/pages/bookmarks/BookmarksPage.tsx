import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { SkeletonTable } from '../../components/Skeleton'
import { useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { X } from 'lucide-react'
import {
  createBookmarkCategory,
  deleteBookmark,
  deleteBookmarkCategory,
  listBookmarkCategories,
  listBookmarks,
  updateBookmark,
} from '../../api/resources'
import type { BookmarkCategory, BookmarkWithArtifact } from '../../api/types'
import { ReviewLedgerPanel } from '../../components/bookmark/ReviewMark'
import { TracedValuesPanel } from './TracedValuesPanel'
import { folderPath, folderTree } from './folderTree'
import { AssignmentQueue } from '../assignments/AssignmentQueue'
import { AssignPanel } from '../assignments/AssignPanel'
import { AssignmentsOverview } from '../assignments/AssignmentsOverview'
import { PersonalBookmarksPanel } from '../assignments/PersonalBookmarksPanel'
import { Modal } from '../../components/Modal'
import { useToast } from '../../components/toast/ToastProvider'
import { downloadFile } from '../../lib/download'
import { formatUtc } from '../../lib/format'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import './bookmarks.css'

const ALL = 'all'
const UNCATEGORIZED = 'uncategorized'

function formatUnix(seconds: number): string {
  return formatUtc(new Date(seconds * 1000).toISOString())
}

export function BookmarksPage() {
  const { caseId } = useParams() as { caseId: string }
  const toast = useToast()
  const queryClient = useQueryClient()
  // The case a mutation must have been sent to for its result to belong here.
  // Assigned during render, not from an effect: a request settling between the
  // switching render and its passive effects would otherwise be tested against
  // the previous case and land under the new one.
  const activeCase = useRef(caseId)
  activeCase.current = caseId

  // The selection is stored together with the case it was made in, and the
  // effective value is derived during render. Resetting it in an effect instead
  // would be one render too late: react-query fires `listBookmarks(caseB,
  // categoryFromA)` on the render where `caseId` has already changed but the
  // effect has not yet run, so a request carrying another case's category id
  // reaches the server before the correction (BUG-262).
  const [selected, setSelected] = useEntityScopedState<string>(caseId, ALL)
  // Categories are per-case, and this page stays mounted across a `:caseId`
  // route change. A category UUID selected in case A does not exist in case B,
  // so listBookmarks(caseB, categoryFromA) returns nothing and the examiner
  // sees an empty list for a case that does have bookmarks. Open modals hold
  // case A rows for the same reason (BUG-262).
  //
  // The modals are scoped rather than closed from a `useEffect`: an effect
  // leaves one committed frame in which "Remove bookmark?" — still naming case
  // A's bookmark — is painted over case B, and Confirm pressed on that frame
  // deletes through case B's endpoint.
  const [showNewCategory, setShowNewCategory] = useEntityScopedState(
    caseId,
    false,
  )
  const [deleteCategoryTarget, setDeleteCategoryTarget] =
    useEntityScopedState<BookmarkCategory | null>(caseId, null)
  const [editTarget, setEditTarget] =
    useEntityScopedState<BookmarkWithArtifact | null>(caseId, null)
  const [removeTarget, setRemoveTarget] =
    useEntityScopedState<BookmarkWithArtifact | null>(caseId, null)

  const categoriesQuery = useQuery({
    queryKey: ['bookmarks', caseId, 'categories'],
    queryFn: () => listBookmarkCategories(caseId),
  })

  const categoryParam =
    selected === ALL || selected === UNCATEGORIZED ? undefined : selected
  const bookmarksQuery = useQuery({
    queryKey: ['bookmarks', caseId, 'list', categoryParam ?? ALL],
    queryFn: () => listBookmarks(caseId, categoryParam),
  })

  const invalidate = (forCase: string) =>
    queryClient.invalidateQueries({ queryKey: ['bookmarks', forCase] })

  // The delete goes to the case that was open when `mutate()` ran, but
  // `onSuccess` runs in the latest render's closure. Reading `caseId` there
  // confirmed "Bookmark removed" over case B while the row was deleted from
  // case A, and refreshed B's list while A's kept showing the removed
  // bookmark. Carry the case the request was sent to through the mutation
  // (B6-030), as the filters and hash-set pages already do.
  const deleteCategoryMutation = useMutation({
    mutationFn: (categoryId: string) => {
      const forCase = caseId
      return deleteBookmarkCategory(forCase, categoryId).then(() => ({
        forCase,
      }))
    },
    onSuccess: ({ forCase }, categoryId) => {
      void invalidate(forCase)
      if (forCase !== activeCase.current) return
      if (selected === categoryId) setSelected(ALL)
      setDeleteCategoryTarget(null)
      toast.success('Category deleted')
    },
    onError: (error: Error) => toast.error(error.message),
  })

  const removeMutation = useMutation({
    mutationFn: (artifactId: string) => {
      const forCase = caseId
      return deleteBookmark(forCase, artifactId).then(() => ({ forCase }))
    },
    onSuccess: ({ forCase }) => {
      void invalidate(forCase)
      if (forCase !== activeCase.current) return
      setRemoveTarget(null)
      toast.success('Bookmark removed')
    },
    onError: (error: Error) => toast.error(error.message),
  })

  async function handleExport(format: 'json' | 'csv') {
    try {
      await downloadFile(
        `/cases/${caseId}/bookmarks/export/${format}`,
        `bookmarks-${caseId}.${format}`,
      )
    } catch {
      toast.error(`${format.toUpperCase()} export failed. Try again.`)
    }
  }

  if (categoriesQuery.isPending || bookmarksQuery.isPending) {
    return <SkeletonTable rows={10} cols={5} label="Loading bookmarks" />
  }
  if (categoriesQuery.isError) {
    return <div className="error-note">{categoriesQuery.error.message}</div>
  }
  if (bookmarksQuery.isError) {
    return <div className="error-note">{bookmarksQuery.error.message}</div>
  }

  const categories = categoriesQuery.data
  const bookmarks =
    selected === UNCATEGORIZED
      ? bookmarksQuery.data.items.filter((b) => b.bookmark.category_id === null)
      : bookmarksQuery.data.items
  // A bookmark list is read as the complete set of things someone deliberately
  // marked, so a listing that stopped at the ceiling has to say so here.
  const bookmarksTruncated = bookmarksQuery.data.truncated

  return (
    <div>
      <h1 className="page-title">Bookmarks</h1>
      {bookmarksTruncated && (
        <div className="notice" role="note">
          This list stopped at the page ceiling. More bookmarks exist in this
          case than are shown, so it is not the complete set of marked items.
        </div>
      )}
      {/* The first question at a handover is not "what did A mark" but "what
          did A look at, and what has nobody opened?". The bookmark list below
          answers the first; nothing in the product answered the second, so the
          ledger sits here, above it, where an examiner inheriting a case will
          look — and it states its own limits, because it is a browser-local
          record and must never be mistaken for a case-wide one. */}
      <ReviewLedgerPanel caseId={caseId} />
      {/* Examiner-authored marks of a different shape: not "this artifact
          matters" but "everything that touches this value matters". It sits
          here rather than on the Findings screen because that screen carries
          Séance's own claims and this is the examiner's (§5.13). */}
      <TracedValuesPanel caseId={caseId} />
      {/* Multi-examiner (§3.15): the work assigned to me, and my private
          marks — the "Mine" root. The table below is the "Shared" root, the
          only bookmarks a report prints. */}
      <AssignmentQueue caseId={caseId} />
      <PersonalBookmarksPanel caseId={caseId} />
      <AssignPanel
        caseId={caseId}
        artifactIds={bookmarks.map((b) => b.bookmark.artifact_id)}
      />
      <AssignmentsOverview caseId={caseId} />
      <div className="page-actions">
        <button className="btn" onClick={() => handleExport('json')}>
          Export JSON
        </button>
        <button className="btn" onClick={() => handleExport('csv')}>
          Export CSV
        </button>
      </div>

      <div className="bm-layout">
        <div className="bm-rail">
          <div className="bm-rail-heading">Categories</div>
          <div className="bm-cat-row">
            <button
              className={
                selected === ALL ? 'bm-cat-button selected' : 'bm-cat-button'
              }
              onClick={() => setSelected(ALL)}
            >
              <span className="bm-cat-name">All</span>
            </button>
          </div>
          <div className="bm-cat-row">
            <button
              className={
                selected === UNCATEGORIZED
                  ? 'bm-cat-button selected'
                  : 'bm-cat-button'
              }
              onClick={() => setSelected(UNCATEGORIZED)}
            >
              <span className="bm-cat-name">Uncategorized</span>
            </button>
          </div>
          {folderTree(categories).map(({ category: cat, depth }) => (
            <div
              key={cat.id}
              className="bm-cat-row"
              data-depth={depth}
              style={{ paddingLeft: depth * 14 }}
            >
              <button
                className={
                  selected === cat.id
                    ? 'bm-cat-button selected'
                    : 'bm-cat-button'
                }
                onClick={() => setSelected(cat.id)}
              >
                <span
                  className="bm-dot"
                  style={{ backgroundColor: cat.color }}
                  aria-hidden="true"
                />
                <span className="bm-cat-name">{cat.name}</span>
                {cat.bookmark_count !== undefined && (
                  <span className="bm-cat-count">{cat.bookmark_count}</span>
                )}
              </button>
              <button
                className="bm-cat-delete icon-btn"
                aria-label={`Delete category ${cat.name}`}
                onClick={() => setDeleteCategoryTarget(cat)}
              >
                <X size={13} />
              </button>
            </div>
          ))}
          <div className="bm-rail-foot">
            <button className="btn" onClick={() => setShowNewCategory(true)}>
              New category
            </button>
          </div>
        </div>

        <div className="bm-main">
          {bookmarks.length === 0 ? (
            <div className="empty-state">
              <h3>No bookmarks here</h3>
              <p>
                Bookmark evidence where you find it — the artifact viewer, the
                media gallery, or a row on the Communications page — and it
                collects here. The note you write at that moment is what the
                report prints beside the exhibit, so it is worth writing then
                rather than later.
              </p>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Artifact</th>
                  <th>Type</th>
                  <th>Category</th>
                  <th>Note</th>
                  <th>Examiner</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {bookmarks.map((row) => (
                  <tr key={row.bookmark.id}>
                    <td>
                      <Link
                        to={`/cases/${caseId}/artifacts/${row.bookmark.artifact_id}`}
                        // Bounded HERE, on the screen, with the whole name a
                        // hover away — never in the record, which the CSV
                        // export and the report print as the artifact's name.
                        className="bm-name"
                        title={row.artifact_name}
                      >
                        {row.artifact_name}
                      </Link>
                    </td>
                    <td>
                      <span className="badge">{row.artifact_type}</span>
                    </td>
                    <td>
                      {row.bookmark.category_name ? (
                        <span
                          className="badge bm-category-badge"
                          style={{
                            color: row.bookmark.category_color ?? undefined,
                            borderColor:
                              row.bookmark.category_color ?? undefined,
                          }}
                        >
                          {row.bookmark.category_name}
                        </span>
                      ) : (
                        <span className="bm-cat-count">—</span>
                      )}
                    </td>
                    <td>
                      {row.bookmark.note ? (
                        <span className="bm-note" title={row.bookmark.note}>
                          {row.bookmark.note}
                        </span>
                      ) : (
                        <span className="bm-cat-count">—</span>
                      )}
                    </td>
                    <td>{row.bookmark.examiner ?? '—'}</td>
                    <td className="mono">
                      {formatUnix(row.bookmark.created_at)}
                    </td>
                    <td>
                      <div className="bm-row-actions">
                        <button
                          className="btn"
                          aria-label={`Edit bookmark for ${row.artifact_name}`}
                          onClick={() => setEditTarget(row)}
                        >
                          Edit
                        </button>
                        <button
                          className="btn btn-danger"
                          aria-label={`Remove bookmark for ${row.artifact_name}`}
                          onClick={() => setRemoveTarget(row)}
                        >
                          Remove
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {showNewCategory && (
        <NewCategoryModal
          caseId={caseId}
          categories={categories}
          onClose={() => setShowNewCategory(false)}
          onCreated={(forCase) => {
            setShowNewCategory(false)
            void invalidate(forCase)
          }}
        />
      )}

      {deleteCategoryTarget && (
        <Modal
          title="Delete category"
          onClose={() => setDeleteCategoryTarget(null)}
          footer={
            <>
              <button
                className="btn"
                onClick={() => setDeleteCategoryTarget(null)}
              >
                Cancel
              </button>
              <button
                className="btn btn-danger"
                disabled={deleteCategoryMutation.isPending}
                onClick={() =>
                  deleteCategoryMutation.mutate(deleteCategoryTarget.id)
                }
              >
                Delete
              </button>
            </>
          }
        >
          <p>
            Delete the category "{deleteCategoryTarget.name}"? Bookmarks in it
            become uncategorized.
          </p>
        </Modal>
      )}

      {editTarget && (
        <EditBookmarkModal
          caseId={caseId}
          target={editTarget}
          categories={categories}
          onClose={() => setEditTarget(null)}
          onSaved={(forCase) => {
            setEditTarget(null)
            void invalidate(forCase)
          }}
        />
      )}

      {removeTarget && (
        <Modal
          title="Remove bookmark"
          onClose={() => setRemoveTarget(null)}
          footer={
            <>
              <button className="btn" onClick={() => setRemoveTarget(null)}>
                Cancel
              </button>
              <button
                className="btn btn-danger"
                disabled={removeMutation.isPending}
                onClick={() =>
                  removeMutation.mutate(removeTarget.bookmark.artifact_id)
                }
              >
                Remove
              </button>
            </>
          }
        >
          <p>Remove the bookmark for "{removeTarget.artifact_name}"?</p>
        </Modal>
      )}
    </div>
  )
}

function NewCategoryModal({
  caseId,
  categories,
  onClose,
  onCreated,
}: {
  caseId: string
  /** The folders of this case, offered as the parent. */
  categories: BookmarkCategory[]
  onClose: () => void
  /** Receives the case the category was written to, not the one on screen. */
  onCreated: (forCase: string) => void
}) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [color, setColor] = useState('#e5a13c')
  const [parentId, setParentId] = useState('')

  const createMutation = useMutation({
    mutationFn: () => {
      const forCase = caseId
      return createBookmarkCategory(forCase, {
        name: name.trim(),
        color,
        // Omitted, not null, for the top level: the server reads absence as "no
        // parent".
        ...(parentId ? { parent_id: parentId } : {}),
      }).then(() => forCase)
    },
    onSuccess: onCreated,
    onError: (error: Error) => toast.error(error.message),
  })

  return (
    <Modal
      title="New category"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            disabled={!name.trim() || createMutation.isPending}
            onClick={() => createMutation.mutate()}
          >
            Create
          </button>
        </>
      }
    >
      <div className="bm-form-row">
        <label htmlFor="bm-new-cat-name">Name</label>
        <input
          id="bm-new-cat-name"
          className="input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoFocus
        />
      </div>
      <div className="bm-form-row">
        <label htmlFor="bm-new-cat-parent">Parent folder</label>
        <select
          id="bm-new-cat-parent"
          className="input"
          value={parentId}
          onChange={(e) => setParentId(e.target.value)}
        >
          <option value="">— top level —</option>
          {folderTree(categories).map(({ category }) => (
            <option key={category.id} value={category.id}>
              {folderPath(categories, category.id)}
            </option>
          ))}
        </select>
      </div>
      <div className="bm-form-row">
        <label htmlFor="bm-new-cat-color">Color</label>
        <input
          id="bm-new-cat-color"
          className="bm-color-input"
          type="color"
          value={color}
          onChange={(e) => setColor(e.target.value)}
        />
      </div>
    </Modal>
  )
}

function EditBookmarkModal({
  caseId,
  target,
  categories,
  onClose,
  onSaved,
}: {
  caseId: string
  target: BookmarkWithArtifact
  categories: BookmarkCategory[]
  onClose: () => void
  /** Receives the case the bookmark was written to, not the one on screen. */
  onSaved: (forCase: string) => void
}) {
  const toast = useToast()
  const [categoryId, setCategoryId] = useState(
    target.bookmark.category_id ?? '',
  )
  const [note, setNote] = useState(target.bookmark.note ?? '')

  const saveMutation = useMutation({
    mutationFn: () => {
      const forCase = caseId
      return updateBookmark(forCase, target.bookmark.artifact_id, {
        category_id: categoryId || null,
        note: note || null,
      }).then(() => forCase)
    },
    onSuccess: onSaved,
    onError: (error: Error) => toast.error(error.message),
  })

  return (
    <Modal
      title={`Edit bookmark: ${target.artifact_name}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            disabled={saveMutation.isPending}
            onClick={() => saveMutation.mutate()}
          >
            Save
          </button>
        </>
      }
    >
      <div className="bm-form-row">
        <label htmlFor="bm-edit-category">Category</label>
        <select
          id="bm-edit-category"
          className="select"
          value={categoryId}
          onChange={(e) => setCategoryId(e.target.value)}
        >
          <option value="">Uncategorized</option>
          {folderTree(categories).map(({ category: cat }) => (
            <option key={cat.id} value={cat.id}>
              {folderPath(categories, cat.id)}
            </option>
          ))}
        </select>
      </div>
      <div className="bm-form-row">
        <label htmlFor="bm-edit-note">Note</label>
        <textarea
          id="bm-edit-note"
          className="input"
          rows={4}
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
      </div>
    </Modal>
  )
}
