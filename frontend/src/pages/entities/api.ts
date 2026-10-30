import { apiFetch } from '../../api/http'

export interface Entity {
  kind: string
  value: string
  count: number
  artifact_ids: string[]
}

export interface EntitiesResponse {
  entities: Entity[]
  counts_by_kind: Record<string, number>
  scanned_records: number
  truncated: boolean
}

/** Extracted entities (emails, URLs, IPs, MACs, crypto, cards, phones). */
export const getEntities = (caseId: string) =>
  apiFetch<EntitiesResponse>(`/cases/${caseId}/entities`)
