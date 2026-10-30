import { useParams, useSearchParams } from 'react-router-dom'
import type { CategoryView } from '../../components/tree/categories'
import { ArtifactPage } from '../artifact/ArtifactPage'
import { RecordsViewerPage } from '../analysis/RecordsViewerPage'
import { GalleryPage } from '../gallery/GalleryPage'
import { GeoMapPage } from '../geo/GeoMapPage'
import { CommsPage } from '../comms/CommsPage'
import { ExecutionPage } from '../execution/ExecutionPage'
import './workbench.css'

const VIEWS: CategoryView[] = [
  'gallery',
  'videos',
  'audio',
  'geo',
  'comms',
  'execution',
]

/**
 * The workbench content canvas. The single navigator lives in the sidebar
 * (NavigatorPanel) and drives this pane through the URL: `?artifact=` opens an
 * artifact (viewer + inspector), `?type=` a record type's table, `?view=` a
 * category view (Pictures→gallery, Geolocation→map, Chats→comms, Program
 * Execution→execution). Deep-linkable; nothing is rendered twice.
 */
export function WorkbenchPage() {
  const { caseId } = useParams() as { caseId: string }
  const [params] = useSearchParams()

  const artifactId = params.get('artifact') ?? undefined
  const type = params.get('type') ?? undefined
  // Provenance scoping: a record type opened from the Logical navigator while a
  // source filter is active carries `?source=`, so the table shows only that
  // acquisition's rows — matching the count the navigator showed.
  const source = params.get('source') ?? undefined
  const viewParam = params.get('view')
  const view = VIEWS.includes(viewParam as CategoryView)
    ? (viewParam as CategoryView)
    : undefined

  return (
    <div className="wb-content">
      {view === 'gallery' ? (
        <GalleryPage caseId={caseId} />
      ) : view === 'videos' ? (
        <GalleryPage caseId={caseId} kind="videos" />
      ) : view === 'audio' ? (
        <GalleryPage caseId={caseId} kind="audio" />
      ) : view === 'geo' ? (
        <GeoMapPage caseId={caseId} />
      ) : view === 'comms' ? (
        <CommsPage caseId={caseId} />
      ) : view === 'execution' ? (
        <ExecutionPage caseId={caseId} />
      ) : artifactId ? (
        <ArtifactPage caseId={caseId} artifactId={artifactId} embedded />
      ) : type ? (
        <RecordsViewerPage caseId={caseId} type={type} source={source} embedded />
      ) : (
        <div className="empty-state wb-empty">
          <h3>Nothing selected</h3>
          <p>
            Pick an item from the navigator on the left — an artifact from the
            <strong> Physical</strong> tree, or a category from the
            <strong> Logical</strong> tree. Right-click a logical type to run
            analysis on it.
          </p>
        </div>
      )}
    </div>
  )
}
