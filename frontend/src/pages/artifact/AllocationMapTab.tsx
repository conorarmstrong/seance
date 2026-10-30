import { useQuery } from '@tanstack/react-query'
import { ApiRequestError } from '../../api/http'
import { getAllocationMap } from '../../components/viz/api'
import { AllocationMap } from '../../components/viz/AllocationMap'

/**
 * Allocation Map tab for a FileSystem artifact. Renders the cluster-allocation
 * bitmap produced at parse time as a usage grid. A 404 means the parser emitted
 * no allocation map for this filesystem (not every filesystem type carries one).
 */
export function AllocationMapTab({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  const query = useQuery({
    queryKey: ['allocation-map', caseId, artifactId],
    queryFn: () => getAllocationMap(caseId, artifactId),
    retry: false,
  })

  if (query.isPending) {
    return <div className="loading">Loading allocation map…</div>
  }
  if (query.isError) {
    const notFound =
      query.error instanceof ApiRequestError && query.error.status === 404
    return (
      <div className="empty-state">
        <h3>No allocation map</h3>
        <p>
          {notFound
            ? 'This filesystem was parsed without a cluster allocation bitmap.'
            : `Failed to load allocation map: ${query.error.message}`}
        </p>
      </div>
    )
  }

  return (
    <div className="av-diskmap">
      <p className="av-note">
        Cluster allocation across the filesystem. Brighter cells are more heavily
        allocated.
      </p>
      <AllocationMap data={query.data} />
    </div>
  )
}
