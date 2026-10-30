import { useNavigate } from 'react-router-dom'
import { DirTree } from '../files/DirTree'

/**
 * Files tab for a FileSystem artifact: the lazy, expand/collapse folder tree
 * (each level fetched on expand). Selecting a folder opens the full file
 * browser scoped to that path, so the tab stays lightweight and in-context
 * rather than duplicating the browser's grid, filters, and preview.
 */
export function FilesTab({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  const navigate = useNavigate()

  const openBrowser = (path: string | null) => {
    const base = `/cases/${caseId}/files/${artifactId}?view=tree`
    navigate(path ? `${base}&dir=${encodeURIComponent(path)}` : base)
  }

  return (
    <div className="av-files">
      <p className="av-note">
        Folder tree for this filesystem — expand to load each level on demand.
        Click a folder to open it in the file browser.
      </p>
      <DirTree
        caseId={caseId}
        sourceId={artifactId}
        currentDirPath=""
        onSelect={openBrowser}
      />
    </div>
  )
}
