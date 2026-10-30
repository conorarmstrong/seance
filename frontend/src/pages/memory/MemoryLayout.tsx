import { NavLink, Outlet, useParams, useSearchParams } from 'react-router-dom'
import {
  getMemoryImages,
  type AnalysisState,
  type MemoryImageSummary,
  type MemoryImagesResponse,
} from './api'
import type { MemoryContext } from './memoryContext'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import { SkeletonList } from '../../components/Skeleton'
import { formatBytes } from '../../lib/format'
import './memory.css'

/**
 * Shell for the memory-analysis section.
 *
 * It owns the one decision every lens below it depends on: **which capture is
 * being looked at**. A case can hold a laptop RAM capture and a server RAM
 * capture, and blending them would attribute one machine's processes to
 * another. The image id is a URL parameter (`?image=…`) so every view in the
 * section is shareable, bookmarkable and citable in a report, and it is
 * threaded into every query key beneath this shell.
 *
 * The nav entry for this section is unconditional. Making it appear only when
 * the case holds a capture would need a capability probe that does not exist
 * yet; showing it always, with one honest empty state, is the option the design
 * names as the zero-risk fallback.
 */

/**
 * Search params that name something INSIDE one capture and are meaningless —
 * worse, actively misleading — under another.
 *
 * `pid` is the whole reason this list exists. Process ids are small integers
 * that every machine reuses, so `?image=A&pid=123` and `?image=B&pid=123`
 * almost always both resolve. Carrying `pid` across a capture change therefore
 * does not fail visibly: the inspector opens capture B's process 123 under an
 * address that reads as a deliberate selection, and an examiner citing that URL
 * attributes one machine's process to another.
 *
 * `pid` is also the only entry: the params the memory lenses actually read are
 * `image`, `pid`, `severity` and `state`, and the last two are filters over
 * whatever capture is on screen, so they survive deliberately. The list held
 * `focus` and `at` as well, which no lens reads or writes — a list of names
 * that do not exist cannot be verified against the pages it claims to protect,
 * and it invites the next reader to believe the deep links it names are covered.
 */
const CAPTURE_SCOPED_PARAMS = ['pid'] as const

/**
 * Short, option-sized wording for what was done with a capture.
 *
 * A display convenience, not the authority on which states exist — a state the
 * server adds and this map has not caught up with falls back to the server's
 * own wording rather than rendering `undefined`.
 */
const CAPTURE_STATE_LABEL: Record<AnalysisState, string> = {
  analysed: 'analysed',
  discovery_failed: 'profile not established',
  not_analysed: 'not analysed',
}

/**
 * Which capture to open when the address names none.
 *
 * Re-running analysis on one file leaves the case holding a second MemoryImage
 * record for it, and the first is the attempt that failed. Opening the first
 * showed an examiner who had just supplied the missing symbols the same
 * "profile not established, 0 of 35 stages" screen as before, with nothing on
 * the page saying a better answer existed one option down the list (LIVE-016).
 * Preferring the analysed capture is a display default only — it changes which
 * capture is shown first, never which captures exist.
 */
export function preferredCapture(
  images: MemoryImageSummary[],
): MemoryImageSummary | undefined {
  return images.find((image) => image.analysis_state === 'analysed') ?? images[0]
}

/**
 * A capture's name, made unambiguous when the case holds another of the same
 * name. The name is built from the image FORMAT, so every hibernation capture
 * in a case reads "Memory image (windows_hibernation)" — identical text on
 * rows that differ in the only way that matters here.
 */
export function captureLabel(
  image: MemoryImageSummary,
  images: MemoryImageSummary[],
): string {
  const nameOf = (i: MemoryImageSummary) => i.name ?? i.image_id
  const base = nameOf(image)
  const sharing = images.filter((other) => nameOf(other) === base)
  if (sharing.length < 2) return base

  // The state is the first thing worth saying, and the reason the picker was
  // ambiguous in the first place. An unrecognised state falls back to the
  // server's own wording rather than indexing to `undefined` — this map is a
  // display convenience, not the authority on what states exist.
  const state =
    CAPTURE_STATE_LABEL[image.analysis_state] ??
    image.analysis_state_meaning ??
    image.analysis_state
  const labelled = `${base} — ${state}`

  // Two runs can share a name AND a state — both succeeded, or both failed —
  // and then the state alone still leaves two identical options. Whatever else
  // is true, the capture id is unique, so it is what settles it.
  const stateOf = (i: MemoryImageSummary) =>
    CAPTURE_STATE_LABEL[i.analysis_state] ??
    i.analysis_state_meaning ??
    i.analysis_state
  const alsoSharingState = sharing.filter((other) => stateOf(other) === state)
  if (alsoSharingState.length < 2) return labelled
  return `${labelled} · ${image.image_id.slice(0, 8)}`
}

/**
 * The address of a different capture in the same case.
 *
 * What the examiner learns: which capture they are looking at, and nothing
 * about a process that was selected in the previous one. Exported for the test
 * that pins this behaviour.
 */
export function paramsForImage(
  current: URLSearchParams,
  imageId: string,
): URLSearchParams {
  const next = new URLSearchParams(current)
  next.set('image', imageId)
  for (const key of CAPTURE_SCOPED_PARAMS) next.delete(key)
  return next
}

const LENSES: { to: string; label: string; end?: boolean }[] = [
  { to: '', label: 'Overview', end: true },
  { to: 'image', label: 'Image' },
  { to: 'processes', label: 'Processes' },
  { to: 'network', label: 'Network' },
  { to: 'handles', label: 'Handles' },
  { to: 'system', label: 'Services & hives' },
  // "Credential stores", not "Credentials": the lens lists the stores that were
  // resident and what is named in them. Nothing under it is a credential an
  // examiner could use or quote, and a tab label is the first claim the product
  // makes about what it holds.
  { to: 'credentials', label: 'Credential stores' },
  { to: 'findings', label: 'Findings' },
]

export function MemoryLayout() {
  const { caseId } = useParams() as { caseId: string }
  const [params, setParams] = useSearchParams()
  const requested = params.get('image')

  const query = useEntityScopedQuery<MemoryImagesResponse>(caseId, {
    queryKey: ['memory', caseId, 'images'],
    queryFn: () => getMemoryImages(caseId),
    staleTime: Infinity,
    retry: false,
  })

  const images = query.scoped?.images ?? []

  if (query.isPending || query.stale) {
    return (
      <div>
        <h1 className="page-title">Memory</h1>
        <SkeletonList rows={4} label="Loading memory captures" />
      </div>
    )
  }

  if (query.isError) {
    return (
      <div>
        <h1 className="page-title">Memory</h1>
        <div className="error-note" role="note">
          <strong>The memory captures in this case could not be listed.</strong>{' '}
          This is a load error, not an empty result — it does not mean the case
          holds no RAM capture.
        </div>
      </div>
    )
  }

  if (images.length === 0) {
    return (
      <div>
        <h1 className="page-title">Memory</h1>
        <div className="empty-state">
          <h3>No memory capture in this case</h3>
          <p>
            Memory analysis needs a RAM capture: a raw dump, a Windows crash
            dump, LiME, AVML, an ELF core, or a hypervisor saved state. Ingest
            one and this section fills in. Nothing here is a statement about the
            disk evidence already in the case.
          </p>
        </div>
      </div>
    )
  }

  const selected = requested
    ? images.find((image) => image.image_id === requested)
    : preferredCapture(images)

  // A capture id in the URL that this case does not contain: almost always a
  // link copied from another case. Refusing loudly is the only safe answer —
  // silently falling back to the first capture would show one machine's memory
  // under another machine's link.
  if (selected == null) {
    return (
      <div>
        <h1 className="page-title">Memory</h1>
        <div className="error-note" role="note">
          <strong>That capture is not in this case.</strong> The address names
          capture <span className="mono">{requested}</span>, which this case
          does not contain. No results are shown, because showing a different
          capture's results under this link would misattribute them.
        </div>
        <div className="page-actions">
          {images.map((image) => (
            <button
              key={image.image_id}
              type="button"
              className="btn"
              onClick={() => setParams(paramsForImage(params, image.image_id))}
            >
              Open {image.name ?? image.image_id}
            </button>
          ))}
        </div>
      </div>
    )
  }

  const context: MemoryContext = {
    caseId,
    imageId: selected.image_id,
    image: selected,
    scopeKey: `${caseId}/${selected.image_id}`,
  }

  return (
    <div className="mem-shell">
      <div className="mem-head">
        <h1 className="page-title">Memory</h1>
        {images.length > 1 ? (
          <label className="mem-image-picker">
            <span>Capture</span>
            <select
              className="select"
              value={selected.image_id}
              onChange={(event) =>
                setParams(paramsForImage(params, event.target.value))
              }
            >
              {images.map((image) => (
                <option key={image.image_id} value={image.image_id}>
                  {captureLabel(image, images)}
                </option>
              ))}
            </select>
          </label>
        ) : (
          <span className="mem-image-single mono">
            {selected.name ?? selected.image_id}
          </span>
        )}
        <span className="mem-image-facts">
          {formatBytes(selected.addressable_bytes)} addressable ·{' '}
          {selected.architecture ?? 'architecture not established'} ·{' '}
          {selected.analysis_state === 'analysed'
            ? 'analysed'
            : selected.analysis_state === 'discovery_failed'
              ? 'profile not established'
              : 'not analysed'}
        </span>
      </div>

      <nav className="mem-lenses" aria-label="Memory lenses">
        {LENSES.map((lens) => (
          <NavLink
            key={lens.label}
            // Absolute, and carrying the capture id: every lens link is a
            // shareable citation of one capture, not of "whatever is selected".
            to={`/cases/${caseId}/memory${lens.to ? `/${lens.to}` : ''}?image=${encodeURIComponent(selected.image_id)}`}
            end={lens.end}
            className={({ isActive }) =>
              isActive ? 'mem-lens active' : 'mem-lens'
            }
          >
            {lens.label}
          </NavLink>
        ))}
      </nav>

      <Outlet context={context} />
    </div>
  )
}
