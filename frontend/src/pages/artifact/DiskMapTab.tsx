import { useQuery } from '@tanstack/react-query'
import { getDiskMap } from '../../components/viz/api'
import { DiskMap } from '../../components/viz/DiskMap'

/**
 * Disk Map tab for a whole-device artifact (RawEvidence / Container). Renders
 * the proportional partition + unallocated + filesystem strip from the source's
 * disk-region descendants. Each region is clickable and opens its artifact.
 */
export function DiskMapTab({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  const query = useQuery({
    queryKey: ['disk-map', caseId, artifactId],
    queryFn: () => getDiskMap(caseId, artifactId),
  })

  if (query.isPending) {
    return <div className="loading">Loading disk layout…</div>
  }
  if (query.isError) {
    return (
      <div className="error-note">
        Failed to load disk layout: {query.error.message}
      </div>
    )
  }
  const data = query.data
  if (!data || data.regions.length === 0) {
    return (
      <div className="empty-state">
        <h3>No partition layout</h3>
        <p>No partitions, filesystems, or unallocated regions were detected on this source.</p>
      </div>
    )
  }

  return (
    <div className="av-diskmap">
      <p className="av-note">Proportional layout of this source. Click a region to open it.</p>
      <DiskMap caseId={caseId} data={data} />
    </div>
  )
}
