import { Treemap } from '../../components/viz/Treemap'

/**
 * Treemap tab for a FileSystem artifact: an interactive, drill-down size map of
 * its directories and files. Sizes are aggregated on the server one level at a
 * time, so even a filesystem with millions of files never loads whole.
 */
export function TreemapTab({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  return (
    <div className="av-diskmap">
      <p className="av-note">
        Directory and file sizes — each tile's area is proportional to bytes.
        Click a folder to drill in; use the breadcrumb to go back up.
      </p>
      <Treemap caseId={caseId} sourceId={artifactId} />
    </div>
  )
}
