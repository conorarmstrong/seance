import { csrfToken, getToken, notifyUnauthorized } from '../../api/http'

const BASE = '/api/v1'

/**
 * Upload a file as multipart/form-data (field name `file`). `apiFetch`
 * only speaks JSON, so import endpoints use this instead. Uses
 * XMLHttpRequest so upload progress can be reported; Content-Type is
 * left to the browser so the multipart boundary is set correctly.
 */
export function uploadFile<T>(
  path: string,
  file: File,
  onProgress?: (fraction: number) => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', `${BASE}${path}`)

    const token = getToken()
    if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`)
    const csrf = csrfToken()
    if (csrf) xhr.setRequestHeader('x-csrf-token', csrf)

    xhr.upload.addEventListener('progress', (event) => {
      if (event.lengthComputable && onProgress) {
        onProgress(event.loaded / event.total)
      }
    })

    xhr.addEventListener('load', () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText) as T)
        } catch {
          reject(new Error('Upload succeeded but the response was not JSON'))
        }
      } else {
        if (xhr.status === 401) notifyUnauthorized()
        let message = `Upload failed with status ${xhr.status}`
        try {
          const payload = JSON.parse(xhr.responseText)
          if (payload?.error?.message) message = payload.error.message
        } catch {
          // Non-JSON error body; keep default message.
        }
        reject(new Error(message))
      }
    })

    xhr.addEventListener('error', () =>
      reject(new Error('Upload failed: network error')),
    )

    const form = new FormData()
    form.append('file', file)
    xhr.send(form)
  })
}
