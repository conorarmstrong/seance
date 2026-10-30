import { apiFetch } from '../../api/http'
import type { Uuid } from '../../api/types'

// Local contracts for the visualization endpoints. Mirrors serde output.

export type DiskRegionType = 'Partition' | 'UnallocatedSpace' | 'FileSystem'

export interface DiskMapRegion {
  artifact_id: Uuid
  artifact_type: DiskRegionType
  parent_id: Uuid | null
  offset_bytes: number
  size_bytes: number
  /**
   * Null in real data: an APFS volume region carries no name. This was declared
   * `string`, and a consumer that believed the declaration crashed the dashboard
   * to a blank page on the first macOS image (LIVE-018).
   */
  name: string | null
  scheme: string | null
  fs_type: string | null
}

export interface DiskMapResponse {
  total_bytes: number
  regions: DiskMapRegion[]
}

export interface AllocationMapResponse {
  allocation_bitmap_b64: string
  allocation_clusters_per_bucket: number
  allocation_total_clusters: number
  allocation_cluster_size: number
}

export const getDiskMap = (caseId: Uuid, sourceId: Uuid) =>
  apiFetch<DiskMapResponse>(`/cases/${caseId}/sources/${sourceId}/disk_map`)

export const getAllocationMap = (caseId: Uuid, artifactId: Uuid) =>
  apiFetch<AllocationMapResponse>(
    `/cases/${caseId}/artifacts/${artifactId}/allocation_map`,
  )

export interface DirSizeChild {
  name: string
  path: string
  size: number
  file_count: number
  is_dir: boolean
}

export interface DirSizesResponse {
  path: string
  total_size: number
  children: DirSizeChild[]
}

export const getDirSizes = (caseId: Uuid, sourceId: Uuid, path = '') =>
  apiFetch<DirSizesResponse>(
    `/cases/${caseId}/sources/${sourceId}/dir_sizes`,
    path ? { query: { path } } : undefined,
  )
