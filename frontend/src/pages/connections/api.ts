import { apiFetch } from '../../api/http'
import type { CommunicationGraph } from './types'

/** Communication network (participants + weighted links) for a case. */
export const getCommunicationGraph = (caseId: string) =>
  apiFetch<CommunicationGraph>(`/cases/${caseId}/graph/communications`)
