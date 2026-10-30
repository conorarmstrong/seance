import { useMemo, useRef, useState } from 'react'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useParams, useSearchParams } from 'react-router-dom'
import { ContextMenu, type ContextMenuItem } from '../../components/ContextMenu'
import {
  IncompletenessChip,
  useIncompleteness,
} from '../../components/Incompleteness'
import { useToast } from '../../components/toast/ToastProvider'
import {
  MediaGallery,
  type MediaItem,
  type MediaSort,
  type SortOrder,
} from '../../components/media/MediaGallery'
import {
  collectImageIds,
  fetchImagePage,
  listExifRecords,
  listSources,
  type ExifRecord,
  type GalleryImage,
  type MediaKind,
} from './api'
import { buildHashHitIndex, getHashHits } from './hashHits'
import { formatCount } from '../../lib/format'
import {
  listHashSets,
  listModules,
  runModule,
  runModuleBatch,
} from '../../api/resources'
import './gallery.css'

/** Images requested per server page as the grid scrolls. */
const IMAGE_PAGE_SIZE = 100

type MatchFilter = 'all' | 'hits' | 'notable'

function metaString(
  meta: Record<string, unknown> | null | undefined,
  key: string,
): string | null {
  const value = meta?.[key]
  return typeof value === 'string' && value.length > 0 ? value : null
}

/** Friendly label for a module id, e.g. "plugin.media.ocr" -> "OCR". */
function moduleLabel(id: string): string {
  const last = (id.split('.').pop() ?? id).replace(/_/g, ' ')
  return last.length <= 4 && !last.includes(' ') ? last.toUpperCase() : last
}

/** Build parent-id and source-name lookups so images can join their EXIF.
 * The parent_id join is exact; the source_name (filename) fallback is only for
 * records with no parent match. A filename shared by several images across
 * paths/sources is ambiguous, so those names are dropped from the fallback map
 * — attaching no EXIF is correct where attaching the wrong record's GPS/camera
 * /taken time would not be. */
function exifIndex(records: ExifRecord[]) {
  const byParent = new Map<string, ExifRecord>()
  const byName = new Map<string, ExifRecord>()
  const ambiguousNames = new Set<string>()
  for (const rec of records) {
    if (rec.parent_id) byParent.set(rec.parent_id, rec)
    const name = metaString(rec.metadata, 'source_name')
    if (name) {
      if (byName.has(name)) ambiguousNames.add(name)
      else byName.set(name, rec)
    }
  }
  for (const name of ambiguousNames) byName.delete(name)
  return { byParent, byName }
}

/** A file image as a normalized MediaItem. `sourceNameById` resolves the
 * evidence source's display name for a single-source view (unknown per-image in
 * the all-sources view, where the id is the 'all' sentinel). */
function toItem(
  image: GalleryImage,
  sourceNameById: Map<string, string>,
): MediaItem {
  return {
    key: image.id,
    artifactId: image.id,
    name: image.name,
    path: image.path,
    size: image.size,
    modified: image.modified,
    extension: image.extension,
    metadata: image.metadata,
    sourceName: sourceNameById.get(image.sourceId) || image.sourceName || null,
  }
}

export function GalleryPage({
  caseId: caseIdProp,
  kind: kindProp,
}: { caseId?: string; kind?: MediaKind } = {}) {
  const params = useParams() as { caseId?: string }
  const caseId = caseIdProp ?? (params.caseId as string)
  const [search] = useSearchParams()
  const kindParam = search.get('kind')
  const kind: MediaKind =
    kindProp ??
    (kindParam === 'videos' || kindParam === 'audio' ? kindParam : 'pictures')
  const noun =
    kind === 'videos' ? 'videos' : kind === 'audio' ? 'audio files' : 'images'
  const mediaNoun =
    kind === 'videos' ? 'video' : kind === 'audio' ? 'audio file' : 'image'
  const pageTitle =
    kind === 'videos' ? 'Videos' : kind === 'audio' ? 'Audio' : 'Gallery'

  const [source, setSource] = useState<string>('all')
  const [match, setMatch] = useState<MatchFilter>('all')
  const [sort, setSort] = useState<MediaSort>('name')
  const [order, setOrder] = useState<SortOrder>('asc')

  // This page stays mounted across a case switch (the :caseId route param
  // changes in place). `source` holds a source UUID that belongs to the old
  // case; carried into case B it queries a non-existent source id and shows an
  // empty gallery while media exists under "All sources". Reset the view state
  // during render (guarded by a ref, so it runs once per change) rather than in
  // an effect: an effect would commit one render with case B's id and case A's
  // source, which is enough for react-query to fire a listing request for
  // another case's source id before the reset lands (BUG-198).
  const prevCaseId = useRef(caseId)
  if (prevCaseId.current !== caseId) {
    prevCaseId.current = caseId
    setSource('all')
    setMatch('all')
    setSort('name')
    setOrder('asc')
  }

  /** Clicking a column sorts by it; clicking the active one reverses. A new
   * column starts in the direction usually wanted first: A-Z for a name,
   * largest and newest first for size and date. */
  const applySort = (column: MediaSort) => {
    if (column === sort) setOrder((o) => (o === 'asc' ? 'desc' : 'asc'))
    else {
      setSort(column)
      setOrder(column === 'name' ? 'asc' : 'desc')
    }
  }

  const sourcesQuery = useQuery({
    queryKey: ['gallery-sources', caseId],
    queryFn: () => listSources(caseId),
  })

  // Server-paginated: each page is fetched as the grid scrolls, so the browser
  // holds only what has been shown. The hash-hit filter is applied server-side
  // too, so filtering searches every image, not just the loaded pages.
  const imagesQuery = useInfiniteQuery({
    queryKey: ['gallery-images', caseId, source, match, kind, sort, order],
    initialPageParam: 1,
    queryFn: ({ pageParam }) =>
      fetchImagePage(caseId, source, pageParam as number, IMAGE_PAGE_SIZE, {
        known: match === 'all' ? undefined : match === 'notable' ? 'notable' : 'any',
        kind,
        sort,
        order,
      }),
    getNextPageParam: (last) => (last.hasNext ? last.page + 1 : undefined),
  })

  const exifQuery = useQuery({
    queryKey: ['gallery-exif', caseId],
    queryFn: () => listExifRecords(caseId),
    staleTime: Infinity,
    retry: false,
  })
  const exif = useMemo(
    () => exifIndex(exifQuery.data?.records ?? []),
    [exifQuery.data],
  )
  // The EXIF overlay is capped the same way the hash-hit overlay is. Past the
  // cap an image simply has no record in the index, and the lightbox then shows
  // no camera, no capture time and no coordinates — which reads as "this
  // picture carries no EXIF" rather than "we stopped looking".
  const exifTruncated = exifQuery.data?.truncated ?? false

  // Hash-hit overlay: correlate gallery images with case-wide hash matches,
  // classified notable (contraband) vs known via the hash sets' type.
  const hashSetsQuery = useQuery({
    queryKey: ['gallery-hashsets', caseId],
    queryFn: () => listHashSets(caseId),
    staleTime: Infinity,
    retry: false,
  })
  const hashHitsQuery = useQuery({
    queryKey: ['gallery-hashhits', caseId],
    queryFn: () => getHashHits(caseId),
    staleTime: Infinity,
    retry: false,
  })
  const hashIndex = useMemo(
    () =>
      buildHashHitIndex(
        hashHitsQuery.data?.hits ?? [],
        hashSetsQuery.data ?? [],
      ),
    [hashHitsQuery.data, hashSetsQuery.data],
  )
  const hasHashData = hashIndex.size > 0
  // The hash-hit overlay is capped; when the cap is reached, badges and the
  // "hash hits only" filter under-report, so tell the examiner.
  const hashHitsTruncated = hashHitsQuery.data?.truncated ?? false
  // These overlays are retry:false and collapse to empty maps on failure, so a
  // transient API error silently drops every notable/known badge and the
  // hash-hit filter -- indistinguishable from a clean case. Surface the error
  // so an empty overlay is never mistaken for "no hits" (BUG-197).
  const hashOverlayError = hashHitsQuery.isError || hashSetsQuery.isError
  const exifOverlayError = exifQuery.isError

  // Evidence-source display names, so a single-source view can label which
  // source each image came from (BUG-117).
  const sourceNameById = useMemo(() => {
    const map = new Map<string, string>()
    for (const s of sourcesQuery.data ?? []) {
      map.set(s.source_artifact_id, s.name)
    }
    return map
  }, [sourcesQuery.data])

  const images = useMemo(
    () => (imagesQuery.data?.pages ?? []).flatMap((p) => p.images),
    [imagesQuery.data],
  )
  const items = useMemo(
    () => images.map((image) => toItem(image, sourceNameById)),
    [images, sourceNameById],
  )
  const totalImages = imagesQuery.data?.pages[0]?.total ?? 0

  // A picture whose bytes were only partly recovered still renders — as a
  // thumbnail that looks like a picture. Tallied here for the toolbar chip; the
  // metadata rides through `toItem` so `MediaGallery` can also mark WHICH
  // pictures the chip counted, on the tile and in the properties sidebar. A
  // count with nothing marked is not something an examiner can act on.
  const incompleteness = useIncompleteness(images)

  // ---- On-demand ("opt-in") analyses over the gallery images -------------
  const toast = useToast()
  const queryClient = useQueryClient()
  // The case a mutation must have been sent to for its result to belong here.
  const activeCase = useRef(caseId)
  activeCase.current = caseId

  // Modules that run on image files but are opt-in (not run automatically at
  // ingest) — OCR today; face/skin/explicit detection would join here.
  const modulesQuery = useQuery({
    queryKey: ['modules', 'FileEntry'],
    queryFn: () => listModules('FileEntry'),
  })
  const optInModules = useMemo(
    () => (modulesQuery.data ?? []).filter((m) => m.execution_mode === 'OptIn'),
    [modulesQuery.data],
  )

  const batchMutation = useMutation({
    mutationFn: async (moduleId: string) => {
      const forCase = caseId
      // Every image in scope, not merely the pages scrolled so far.
      const collected = await collectImageIds(forCase, source, {
        known: match === 'all' ? undefined : match === 'notable' ? 'notable' : 'any',
        kind,
      })
      const res = await runModuleBatch(forCase, moduleId, collected.ids)
      // The selection can be trimmed on the way in (collectImageIds' cap) as
      // well as on the way out (the server's own batch ceiling). Either way the
      // run does not cover every picture the filter selected, and the toast is
      // the only place that says so.
      return {
        res: { ...res, truncated: res.truncated || collected.truncated },
        forCase,
      }
    },
    onSuccess: ({ res, forCase }, moduleId) => {
      // Always the case the run was queued against, never the one on screen:
      // this page stays mounted across a `:caseId` change and `onSuccess` runs
      // in the latest render's closure (B5-012 class).
      queryClient.invalidateQueries({ queryKey: ['jobs', forCase] })
      const where =
        forCase === activeCase.current
          ? ''
          : ' in the case it was started from, not the one open now'
      toast.success(
        `Queued ${moduleLabel(moduleId)} on ${formatCount(res.targets)} image(s)` +
          (res.truncated ? ' (capped at 5000)' : '') +
          where,
      )
    },
    onError: (err) => toast.error(`Failed to queue analysis: ${err.message}`),
  })
  const singleMutation = useMutation({
    mutationFn: (v: { moduleId: string; artifactId: string }) => {
      const forCase = caseId
      return runModule(forCase, v.artifactId, v.moduleId).then(() => forCase)
    },
    onSuccess: (forCase, v) => {
      queryClient.invalidateQueries({ queryKey: ['jobs', forCase] })
      const where =
        forCase === activeCase.current
          ? ''
          : ' in the case it was started from, not the one open now'
      toast.success(`Queued ${moduleLabel(v.moduleId)} on 1 image` + where)
    },
    onError: (err) => toast.error(`Failed to queue analysis: ${err.message}`),
  })

  const exifFor = (item: MediaItem): ExifRecord | null =>
    exif.byParent.get(item.key) ?? exif.byName.get(item.name) ?? null
  const flagFor = (item: MediaItem) => hashIndex.get(item.key)

  // Per-cell run-analysis entries, appended after the shared bookmark items.
  const analysisItems = (item: MediaItem): ContextMenuItem[] => {
    if (optInModules.length === 0) return []
    return optInModules.map((m) => ({
      label: `Run ${moduleLabel(m.id)} on this image`,
      note: m.id,
      onClick: () =>
        singleMutation.mutate({ moduleId: m.id, artifactId: item.key }),
    }))
  }

  if (sourcesQuery.isError || imagesQuery.isError) {
    const err = sourcesQuery.error ?? imagesQuery.error
    return (
      <div>
        <h1 className="page-title">{pageTitle}</h1>
        <div className="error-note">
          Failed to load {noun}: {(err as Error)?.message}
        </div>
      </div>
    )
  }

  const loading =
    sourcesQuery.isPending || (imagesQuery.isPending && sourcesQuery.isSuccess)

  return (
    <MediaGallery
      caseId={caseId}
      title={pageTitle}
      noun={noun}
      mediaNoun={mediaNoun}
      items={items}
      total={totalImages}
      loading={loading}
      sort={sort}
      order={order}
      onSort={applySort}
      onSortChange={(s, o) => {
        setSort(s)
        setOrder(o)
      }}
      hasNextPage={imagesQuery.hasNextPage}
      isFetchingNextPage={imagesQuery.isFetchingNextPage}
      onLoadMore={() => void imagesQuery.fetchNextPage()}
      flagFor={flagFor}
      exifFor={exifFor}
      extraCellMenuItems={analysisItems}
      emptyState={
        <div className="empty-state">
          <h3>No {noun}</h3>
          <p>This case has no {noun} in the selected source.</p>
        </div>
      }
      toolbarStart={
        <>
          <div className="gl-filter">
            <label htmlFor="gl-source">Source</label>
            <select
              id="gl-source"
              className="select"
              value={source}
              onChange={(e) => setSource(e.target.value)}
            >
              <option value="all">All sources</option>
              {(sourcesQuery.data ?? []).map((s) => (
                <option key={s.source_artifact_id} value={s.source_artifact_id}>
                  {s.name}
                </option>
              ))}
            </select>
          </div>
          {hasHashData && (
            <div className="gl-filter">
              <label htmlFor="gl-match">Hash matches</label>
              <select
                id="gl-match"
                className="select"
                value={match}
                onChange={(e) => setMatch(e.target.value as MatchFilter)}
              >
                <option value="all">All images</option>
                <option value="hits">Hash hits only</option>
                <option value="notable">Notable only</option>
              </select>
              {hashHitsTruncated && (
                <span
                  className="gl-warn"
                  role="note"
                  title="Too many hash hits to index them all; notable/known badges and the hash-hits filter under-report on this case."
                >
                  ⚠ badges partial
                </span>
              )}
            </div>
          )}
          {exifTruncated && (
            <div className="gl-filter">
              <span
                className="gl-warn"
                role="note"
                title="Too many EXIF records in this case to index them all. Images past the cap show no camera, capture time or GPS in the lightbox — that is this cap, not a picture without EXIF."
              >
                ⚠ EXIF annotation partial
              </span>
            </div>
          )}
          {incompleteness.affected > 0 && (
            <div className="gl-filter">
              <IncompletenessChip summary={incompleteness} noun={noun} />
            </div>
          )}
          {(hashOverlayError || exifOverlayError) && (
            <div className="gl-filter">
              <span
                className="gl-warn"
                role="alert"
                title="This overlay failed to load, so it fell back to empty. Notable/known badges, the hash-hit filter and/or EXIF annotations may be missing. This does NOT mean the case has no hits -- retry or reload."
              >
                ⚠{' '}
                {hashOverlayError && exifOverlayError
                  ? 'hash-hit and EXIF overlays'
                  : hashOverlayError
                    ? 'hash-hit overlay'
                    : 'EXIF overlay'}{' '}
                failed to load
              </span>
            </div>
          )}
        </>
      }
      toolbarEnd={
        optInModules.length > 0 && items.length > 0 ? (
          <BatchAnalysisButton
            modules={optInModules.map((m) => ({ id: m.id, label: moduleLabel(m.id) }))}
            noun={noun}
            total={totalImages}
            onRun={(id) => batchMutation.mutate(id)}
          />
        ) : undefined
      }
    />
  )
}

/** Toolbar button that opens a menu to run an opt-in analysis over the whole set. */
function BatchAnalysisButton({
  modules,
  noun,
  total,
  onRun,
}: {
  modules: { id: string; label: string }[]
  noun: string
  total: number
  onRun: (moduleId: string) => void
}) {
  const [menu, setMenu] = useState<{ x: number; y: number } | null>(null)
  return (
    <>
      <button
        type="button"
        className="button gl-analyze"
        title="Run an on-demand analysis (e.g. OCR) across these images"
        onClick={(e) => {
          const r = e.currentTarget.getBoundingClientRect()
          setMenu({ x: r.left, y: r.bottom + 4 })
        }}
      >
        Run analysis ▾
      </button>
      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          items={modules.map((m) => ({
            label: `Run ${m.label} on all ${formatCount(total)} ${noun}`,
            note: m.id,
            onClick: () => {
              onRun(m.id)
              setMenu(null)
            },
          }))}
          onClose={() => setMenu(null)}
        />
      )}
    </>
  )
}
