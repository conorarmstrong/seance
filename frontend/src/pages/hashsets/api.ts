import { apiFetch } from '../../api/http'

export interface HashHit {
  artifact_id: string
  name: string
  path: string
  hash_set_id: string
  hash_set_name: string
  matched_hash: string
  algorithm: string
}

export interface HashHitsResponse {
  hits: HashHit[]
  total: number
  page: number
  page_size: number
}

export const getHashHits = (
  caseId: string,
  params: { hash_set_id?: string; page: number; page_size: number },
) =>
  apiFetch<HashHitsResponse>(`/cases/${caseId}/hash_hits`, {
    query: { ...params },
  })
