import { lazy, type ComponentType } from 'react'
import {
  Link,
  Navigate,
  Route,
  Routes,
  useLocation,
  useParams,
  useSearchParams,
} from 'react-router-dom'
import { LoginPage } from '../auth/LoginPage'
import { RequireAuth } from './RequireAuth'
import { CaseLayout } from './CaseLayout'
import { CasesPage } from '../pages/cases/CasesPage'

// The case-detail pages are code-split: each loads its own chunk on first
// navigation instead of shipping in the initial bundle. The shell (login, auth
// guard, CaseLayout, the cases landing) stays eager so the first paint needs no
// extra round trip. CaseLayout wraps its <Outlet/> in a Suspense boundary, so a
// page chunk loading only swaps the content area, not the whole shell.
//
// React.lazy wants a module whose `default` is the component; these pages use
// named exports, so map the named export to `default`.
//
// The constraint is on the KEY, not on the whole module: `name` has to be a
// real export of the module it is paired with, so a renamed or mistyped page
// export fails the build rather than resolving to `undefined` and blanking the
// route at runtime. Requiring every export to be a component would be wrong —
// a page module may legitimately export a helper alongside its component, as
// MemoryLayout does with `paramsForImage` (which its test pins), and that is
// not a reason to reject the module.
//
// The page's own prop type is carried through rather than flattened to "no
// props": a couple of routes are adapters that read a search parameter and hand
// it to the page (RecordsViewerRoute and `?source=`), and flattening would make
// the compiler accept any prop name at all on those calls — including a
// misspelled one, which would silently drop the provenance scope it was passing.
const named = <M extends Record<string, unknown>, K extends keyof M & string>(
  loader: () => Promise<M>,
  name: K,
) =>
  lazy(() =>
    loader().then((m) => ({
      default: m[name] as M[K] extends ComponentType<infer P>
        ? ComponentType<P>
        : ComponentType<Record<string, never>>,
    })),
  )

const CaseDashboardPage = named(
  () => import('../pages/dashboard/CaseDashboardPage'),
  'CaseDashboardPage',
)
const WorkbenchPage = named(
  () => import('../pages/workbench/WorkbenchPage'),
  'WorkbenchPage',
)
const TimelinePage = named(() => import('../pages/timeline/TimelinePage'), 'TimelinePage')
const SearchPage = named(() => import('../pages/search/SearchPage'), 'SearchPage')
const AnalysisIndexPage = named(
  () => import('../pages/analysis/AnalysisIndexPage'),
  'AnalysisIndexPage',
)
const RecordsViewerPage = named(
  () => import('../pages/analysis/RecordsViewerPage'),
  'RecordsViewerPage',
)
const GalleryPage = named(() => import('../pages/gallery/GalleryPage'), 'GalleryPage')
const GeoMapPage = named(() => import('../pages/geo/GeoMapPage'), 'GeoMapPage')
const ConnectionsPage = named(
  () => import('../pages/connections/ConnectionsPage'),
  'ConnectionsPage',
)
const ExecutionPage = named(() => import('../pages/execution/ExecutionPage'), 'ExecutionPage')
const SystemInfoPage = named(
  () => import('../pages/system/SystemInfoPage'),
  'SystemInfoPage',
)
const DuplicatesPage = named(
  () => import('../pages/duplicates/DuplicatesPage'),
  'DuplicatesPage',
)
const FindingsPage = named(
  () => import('../pages/findings/FindingsPage'),
  'FindingsPage',
)
const CommsPage = named(() => import('../pages/comms/CommsPage'), 'CommsPage')
const EntitiesPage = named(() => import('../pages/entities/EntitiesPage'), 'EntitiesPage')
const ArtifactPage = named(() => import('../pages/artifact/ArtifactPage'), 'ArtifactPage')
const FileGridPage = named(() => import('../pages/files/FileGridPage'), 'FileGridPage')
const BookmarksPage = named(() => import('../pages/bookmarks/BookmarksPage'), 'BookmarksPage')
const FiltersPage = named(() => import('../pages/filters/FiltersPage'), 'FiltersPage')
const HashSetsPage = named(() => import('../pages/hashsets/HashSetsPage'), 'HashSetsPage')
const AuditLogPage = named(() => import('../pages/audit/AuditLogPage'), 'AuditLogPage')
const CaseSettingsPage = named(
  () => import('../pages/settings/CaseSettingsPage'),
  'CaseSettingsPage',
)
const HelpPage = named(() => import('../pages/help/HelpPage'), 'HelpPage')

// Memory analysis is a cross-type investigator workflow, not one record type,
// so it gets a shell with its own sub-nav rather than eleven top-level entries.
// The shell owns the selected capture; every lens beneath it reads that
// selection from the URL, which is what makes `…/memory/processes?image=…&pid=…`
// a citation an examiner can put in a report.
const MemoryLayout = named(
  () => import('../pages/memory/MemoryLayout'),
  'MemoryLayout',
)
const MemoryOverviewPage = named(
  () => import('../pages/memory/MemoryOverviewPage'),
  'MemoryOverviewPage',
)
const ImageProfilePage = named(
  () => import('../pages/memory/ImageProfilePage'),
  'ImageProfilePage',
)
const ProcessTreePage = named(
  () => import('../pages/memory/ProcessTreePage'),
  'ProcessTreePage',
)
const MemoryNetworkPage = named(
  () => import('../pages/memory/MemoryNetworkPage'),
  'MemoryNetworkPage',
)
const MemoryHandlesPage = named(
  () => import('../pages/memory/MemoryHandlesPage'),
  'MemoryHandlesPage',
)
const MemorySystemPage = named(
  () => import('../pages/memory/MemorySystemPage'),
  'MemorySystemPage',
)
const MemoryCredentialsPage = named(
  () => import('../pages/memory/MemoryCredentialsPage'),
  'MemoryCredentialsPage',
)
const MemoryFindingsPage = named(
  () => import('../pages/memory/MemoryFindingsPage'),
  'MemoryFindingsPage',
)

/**
 * The canonical address for whatever a `/workbench?…` URL selected, or `null`
 * when it selected nothing.
 *
 * Every major view used to have two addresses: the standalone route
 * (`/cases/X/gallery`) and the workbench query-param form
 * (`/cases/X/workbench?view=gallery`). They render the same evidence, so a
 * bookmark, a shared link and the Back button disagreed about identity, and two
 * examiners citing "the same" screen cited different URLs — one of which showed
 * the artifact ancestry breadcrumb and one of which did not.
 *
 * The standalone route wins because it is the one that can be named: it is one
 * address per view, it is what the nav rail and the palette point at, and it is
 * what a witness statement can quote without a query string to explain. The
 * workbench keeps its route and redirects, because links, notes and bookmarks
 * written against the old form still exist.
 *
 * Everything the old address carried is carried across. `?source=` in
 * particular is the parameter that stops rows recovered from one database being
 * read under another database's heading; a redirect that dropped it would
 * manufacture exactly the misattribution it exists to prevent.
 */
export function canonicalWorkbenchPath(
  caseId: string,
  params: URLSearchParams,
): string | null {
  // The workbench resolved view, then artifact, then type. Keep that order:
  // any other choice changes what an already-written URL shows.
  const rest = new URLSearchParams(params)
  // An empty value is treated as absent, not as a selection: `?artifact=` names
  // no artifact, and resolving it would build `/artifacts/` — an address that
  // matches nothing — out of a URL that simply had nothing selected.
  const take = (name: string) => {
    const value = rest.get(name)
    rest.delete(name)
    return value === '' ? null : value
  }
  const view = take('view')
  const artifact = take('artifact')
  const type = take('type')

  const withRest = (path: string) => {
    const query = rest.toString()
    return query ? `${path}?${query}` : path
  }
  const under = (suffix: string) => `/cases/${caseId}/${suffix}`

  if (view !== null) {
    switch (view) {
      // Pictures, videos and audio are one page distinguished only by `?kind=`,
      // so the kind has to survive the redirect or all three collapse into
      // pictures.
      case 'gallery':
        return withRest(under('gallery'))
      case 'videos':
        rest.set('kind', 'videos')
        return withRest(under('gallery'))
      case 'audio':
        rest.set('kind', 'audio')
        return withRest(under('gallery'))
      case 'geo':
        return withRest(under('geo'))
      case 'comms':
        return withRest(under('communications'))
      case 'execution':
        return withRest(under('execution'))
      // An unrecognised view is not a redirect target. The workbench showed its
      // "nothing selected" state for it, and so should this.
      default:
        return null
    }
  }
  if (artifact !== null) {
    return withRest(under(`artifacts/${encodeURIComponent(artifact)}`))
  }
  if (type !== null) {
    return withRest(under(`analysis/${encodeURIComponent(type)}`))
  }
  return null
}

/**
 * `/cases/:caseId/workbench` — kept as the address of the old selections and
 * redirected to the canonical one, replacing the history entry so that Back
 * from the destination goes where the examiner came from rather than bouncing
 * through the redirect.
 */
function WorkbenchRoute() {
  const { caseId } = useParams() as { caseId: string }
  const [params] = useSearchParams()
  const canonical = canonicalWorkbenchPath(caseId, params)
  if (canonical) return <Navigate to={canonical} replace />
  return <WorkbenchPage />
}

/**
 * `/cases/:caseId/analysis/:type` — the standalone records viewer, wired to the
 * provenance scope in the URL.
 *
 * `?source=` was only ever reachable as a prop from the workbench, so a deep
 * link into a record type could not say which acquisition its rows came from.
 * Reading it here means the canonical address carries the scope, which is what
 * makes the workbench redirect above lossless.
 */
function RecordsViewerRoute() {
  const [params] = useSearchParams()
  return <RecordsViewerPage source={params.get('source') ?? undefined} />
}

/**
 * Addresses that are one segment short of a real view, and the view they name.
 *
 * `/cases/<id>/image` was observed live on a real case. It is neither a broken
 * link nor a missing page — nothing in the app points at it and the page is
 * built and routed, at `memory/image`. It is the memory section's address with
 * the section dropped, which is what a hand-typed or hand-truncated URL looks
 * like.
 *
 * These are SUGGESTIONS, not redirects, on purpose. In this product "image"
 * means both a disk image and a RAM capture, so silently landing someone on the
 * memory profile asserts which one they meant; a screen that may be quoted
 * under oath does not guess. `system` is left out for the same reason — it
 * could be the memory lens or System Info, and there is no way to tell.
 */
const MEMORY_LENS_SUGGESTIONS: Record<string, string> = {
  image: 'Image',
  processes: 'Processes',
  network: 'Network',
  handles: 'Handles',
  credentials: 'Credential stores',
  findings: 'Findings',
}

export function suggestedCaseRoute(
  path: string,
): { to: string; label: string } | null {
  const lens = MEMORY_LENS_SUGGESTIONS[path]
  if (lens) return { to: `memory/${path}`, label: `Memory → ${lens}` }
  return null
}

/**
 * An address inside a case that matches no view.
 *
 * It keeps the case shell, which the app-level not-found cannot: an examiner
 * following a colleague's stale link lands with the rail, the ⌘K palette and
 * the evidence navigator still around them, in the case they were sent to.
 * Falling through to the app-level `*` instead threw them out to the cases list
 * with the case they were trying to open no longer on screen.
 */
function CaseNotFoundPage() {
  const { caseId } = useParams() as { caseId: string }
  const location = useLocation()
  const path = location.pathname.replace(`/cases/${caseId}/`, '')
  const suggestion = suggestedCaseRoute(path)

  return (
    <div className="empty-state">
      <h3>No view at this address</h3>
      <p>
        This case does not have a view at{' '}
        <span className="mono">{path}</span>. Nothing is missing from the case —
        the address itself matches no view in this product.
      </p>
      {suggestion && (
        <p>
          Did you mean{' '}
          <Link to={`/cases/${caseId}/${suggestion.to}`}>{suggestion.label}</Link>?
        </p>
      )}
      <Link to={`/cases/${caseId}`}>Case dashboard</Link>
    </div>
  )
}

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<RequireAuth />}>
        <Route path="/" element={<CasesPage />} />
        <Route path="/cases/:caseId" element={<CaseLayout />}>
          <Route index element={<CaseDashboardPage />} />
          <Route path="workbench" element={<WorkbenchRoute />} />
          <Route path="timeline" element={<TimelinePage />} />
          <Route path="search" element={<SearchPage />} />
          <Route path="analysis" element={<AnalysisIndexPage />} />
          <Route path="analysis/:type" element={<RecordsViewerRoute />} />
          <Route path="gallery" element={<GalleryPage />} />
          <Route path="geo" element={<GeoMapPage />} />
          <Route path="connections" element={<ConnectionsPage />} />
          <Route path="execution" element={<ExecutionPage />} />
          <Route path="system-info" element={<SystemInfoPage />} />
          <Route path="duplicates" element={<DuplicatesPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="communications" element={<CommsPage />} />
          <Route path="entities" element={<EntitiesPage />} />
          <Route path="memory" element={<MemoryLayout />}>
            <Route index element={<MemoryOverviewPage />} />
            <Route path="image" element={<ImageProfilePage />} />
            <Route path="processes" element={<ProcessTreePage />} />
            <Route path="network" element={<MemoryNetworkPage />} />
            <Route path="handles" element={<MemoryHandlesPage />} />
            <Route path="system" element={<MemorySystemPage />} />
            <Route path="credentials" element={<MemoryCredentialsPage />} />
            <Route path="findings" element={<MemoryFindingsPage />} />
          </Route>
          <Route path="artifacts/:artifactId" element={<ArtifactPage />} />
          <Route path="files/:sourceId" element={<FileGridPage />} />
          <Route path="bookmarks" element={<BookmarksPage />} />
          <Route path="filters" element={<FiltersPage />} />
          <Route path="hash-sets" element={<HashSetsPage />} />
          <Route path="audit" element={<AuditLogPage />} />
          <Route path="settings" element={<CaseSettingsPage />} />
          <Route path="help" element={<HelpPage />} />
          <Route path="*" element={<CaseNotFoundPage />} />
        </Route>
      </Route>
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}

function NotFoundPage() {
  return (
    <div className="empty-state">
      <h3>Page not found</h3>
      <p>This address does not match any view.</p>
      <Link to="/">Back to cases</Link>
    </div>
  )
}
