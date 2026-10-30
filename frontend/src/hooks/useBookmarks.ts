import { useCallback, useMemo } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '../api/http'
import {
  createBookmark,
  deleteBookmark,
  getBookmarkedIds,
  listBookmarkCategories,
  updateBookmark,
} from '../api/resources'
import type { ArtifactBookmark, BookmarkCategory } from '../api/types'

/**
 * One case's bookmarks, as every capture surface needs them.
 *
 * The plumbing this replaces was written twice — once in the artifact viewer,
 * once in the media gallery — and both copies threw away the two fields the
 * capture endpoint has always accepted: the category and the note. The result
 * was a product where the WHY of a finding had to be typed later, on a
 * different page, against a row in a flat list of hundreds, which in practice
 * meant it was never typed at all. Everything a surface needs to capture at the
 * moment of discovery lives here so a third copy is never written.
 *
 * ## The unknown state is not the unmarked state
 *
 * `isBookmarked` returns `null` while the id set is in flight or its load
 * failed, and callers must render that differently from `false`. A table that
 * paints five hundred hollow stars because a request has not landed is telling
 * an examiner that nothing in front of them was marked, which is a claim about
 * the case made out of a claim about the network.
 *
 * ## Why failures are returned rather than toasted
 *
 * This hook takes no toast context. A capture control is rendered inside table
 * cells on pages that may not sit under a `ToastProvider`, and `useToast`
 * throws when there is none — one missing provider would take down every row of
 * a table rather than one notification. A failed write is returned as
 * `lastError` and shown where the examiner is looking, which is also where they
 * can tell whether their note was recorded.
 */

export interface BookmarkDraft {
  /** Category to file the capture under, or undefined for uncategorised. */
  categoryId?: string
  /** The examiner's reason, in their words. Blank is stored as absent. */
  note?: string
}

export interface UseBookmarks {
  /** True once the id set has been loaded and can be answered from. */
  idsLoaded: boolean
  /** Why the id set could not be loaded, if it could not. */
  idsError: string | null
  /** True / false once loaded; null while unknown. See the module comment. */
  isBookmarked: (artifactId: string) => boolean | null
  /** Categories a capture may be filed under, empty until they load. */
  categories: BookmarkCategory[]
  /** Create a bookmark, carrying the note and category as typed. */
  add: (artifactId: string, draft?: BookmarkDraft) => Promise<void>
  /** Amend an existing bookmark's note or category. */
  update: (artifactId: string, draft: BookmarkDraft) => Promise<void>
  /** Remove a bookmark. */
  remove: (artifactId: string) => Promise<void>
  /** Read one bookmark back, so an edit starts from what is actually stored. */
  fetchOne: (artifactId: string) => Promise<ArtifactBookmark>
  /** True while any of the above is in flight. */
  busy: boolean
  /** Why the last write failed, if it did. */
  lastError: string | null
}

/**
 * A note as it should be sent: trimmed, and absent rather than empty.
 *
 * An empty string in the note column is indistinguishable on the Bookmarks page
 * and in the report from a note that was written and then blanked. "No note"
 * is the honest record of a fast capture, and it is what the em-dash in the
 * report renders.
 */
function cleanNote(note: string | undefined): string | undefined {
  const trimmed = note?.trim()
  return trimmed ? trimmed : undefined
}

export function useBookmarks(caseId: string): UseBookmarks {
  const queryClient = useQueryClient()

  const idsQuery = useQuery({
    // Under the ['bookmarks', caseId, …] prefix that every bookmark surface
    // invalidates, so a capture made anywhere refreshes the marks everywhere.
    queryKey: ['bookmarks', caseId, 'ids'],
    queryFn: () => getBookmarkedIds(caseId),
  })
  const categoriesQuery = useQuery({
    queryKey: ['bookmarks', caseId, 'categories'],
    queryFn: () => listBookmarkCategories(caseId),
  })

  const ids = useMemo(
    () => (idsQuery.data ? new Set(idsQuery.data) : null),
    [idsQuery.data],
  )

  const isBookmarked = useCallback(
    (artifactId: string) => (ids ? ids.has(artifactId) : null),
    [ids],
  )

  const invalidate = (forCase: string) =>
    queryClient.invalidateQueries({ queryKey: ['bookmarks', forCase] })

  // Every mutation carries the case it was sent to through its own result
  // rather than reading `caseId` in `onSuccess`, which runs in the latest
  // render's closure: a capture made in case A while the examiner navigates to
  // case B otherwise refreshes B's lists and confirms itself over B's screen
  // (the B5-012 / B6-030 class this codebase has fixed repeatedly).
  const addMutation = useMutation({
    mutationFn: async (v: { artifactId: string; draft?: BookmarkDraft }) => {
      const forCase = caseId
      await createBookmark(forCase, {
        artifact_id: v.artifactId,
        ...(v.draft?.categoryId ? { category_id: v.draft.categoryId } : {}),
        ...(cleanNote(v.draft?.note) ? { note: cleanNote(v.draft?.note) } : {}),
      })
      return forCase
    },
    onSuccess: (forCase) => void invalidate(forCase),
  })

  const updateMutation = useMutation({
    mutationFn: async (v: { artifactId: string; draft: BookmarkDraft }) => {
      const forCase = caseId
      await updateBookmark(forCase, v.artifactId, {
        category_id: v.draft.categoryId || null,
        note: cleanNote(v.draft.note) ?? null,
      })
      return forCase
    },
    onSuccess: (forCase) => void invalidate(forCase),
  })

  const removeMutation = useMutation({
    mutationFn: async (artifactId: string) => {
      const forCase = caseId
      await deleteBookmark(forCase, artifactId)
      return forCase
    },
    onSuccess: (forCase) => void invalidate(forCase),
  })

  const add = useCallback(
    async (artifactId: string, draft?: BookmarkDraft) => {
      await addMutation.mutateAsync({ artifactId, draft })
    },
    // `mutateAsync` is stable for the life of the mutation object, and the
    // object is recreated per render by react-query; depending on the whole
    // mutation would give every consumer a new callback every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [addMutation.mutateAsync],
  )
  const update = useCallback(
    async (artifactId: string, draft: BookmarkDraft) => {
      await updateMutation.mutateAsync({ artifactId, draft })
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [updateMutation.mutateAsync],
  )
  const remove = useCallback(
    async (artifactId: string) => {
      await removeMutation.mutateAsync(artifactId)
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [removeMutation.mutateAsync],
  )

  // The single-bookmark read has no binding in `api/resources.ts` because
  // nothing needed it until a capture control had to open an EXISTING bookmark
  // for editing without loading the whole list. Reading the stored note before
  // showing it is what stops an edit silently blanking a note the control never
  // saw.
  const fetchOne = useCallback(
    (artifactId: string) =>
      apiFetch<ArtifactBookmark>(`/cases/${caseId}/bookmarks/${artifactId}`),
    [caseId],
  )

  return {
    idsLoaded: ids != null,
    idsError: idsQuery.isError ? idsQuery.error.message : null,
    isBookmarked,
    categories: categoriesQuery.data ?? [],
    add,
    update,
    remove,
    fetchOne,
    busy:
      addMutation.isPending ||
      updateMutation.isPending ||
      removeMutation.isPending,
    lastError:
      (addMutation.error ?? updateMutation.error ?? removeMutation.error)
        ?.message ?? null,
  }
}
