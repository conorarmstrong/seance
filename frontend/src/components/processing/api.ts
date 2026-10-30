import { apiFetch } from '../../api/http'

export const cancelProcessing = (caseId: string) =>
  apiFetch<{ cancelling: boolean }>(`/cases/${caseId}/processing/cancel`, {
    method: 'POST',
  })
