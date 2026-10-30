const BASE = '/api/v1'
// Key an older build used to mirror the JWT into localStorage. The token is now
// kept in memory only (BUG-200): the API also authenticates same-origin requests
// via the HttpOnly `seance_auth` cookie, so persisting the JWT bought nothing but
// a wider XSS blast radius. We still purge this key so an upgraded client scrubs
// any token a prior build left behind.
const LEGACY_TOKEN_KEY = 'seance_token'

let token: string | null = null
// One-time migration: drop any JWT a prior build persisted here.
localStorage.removeItem(LEGACY_TOKEN_KEY)

export function setToken(value: string) {
  // In-memory only — deliberately never written to localStorage (BUG-200).
  token = value
}

export function getToken(): string | null {
  return token
}

export function clearToken() {
  token = null
  // Scrub any legacy persisted token as well.
  localStorage.removeItem(LEGACY_TOKEN_KEY)
}

type UnauthorizedListener = () => void
const unauthorizedListeners = new Set<UnauthorizedListener>()

/** Register a callback fired whenever the API answers 401. */
export function onUnauthorized(listener: UnauthorizedListener): () => void {
  unauthorizedListeners.add(listener)
  return () => unauthorizedListeners.delete(listener)
}

/** Fire the 401 listeners (session clear). Exported for the XHR upload path,
 * which has an HTTP status but no fetch Response to hand to checkUnauthorized. */
export function notifyUnauthorized(): void {
  for (const listener of unauthorizedListeners) listener()
}

/**
 * Fire the 401 listeners when a raw fetch response is Unauthorized, then return
 * the response unchanged. Raw-fetch helpers (download, upload, content/thumbnail
 * blobs) route their responses through this so a 401 clears the session exactly
 * as it does inside apiFetch, instead of throwing a generic error that leaves a
 * stale session in place.
 */
export function checkUnauthorized(response: Response): Response {
  if (response.status === 401) notifyUnauthorized()
  return response
}

export class ApiRequestError extends Error {
  readonly code: string
  readonly status: number
  readonly details?: unknown

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message)
    this.name = 'ApiRequestError'
    this.status = status
    this.code = code
    this.details = details
  }
}

/**
 * Percent-decode `value`, or hand back exactly what was received when it is
 * not valid percent-encoding.
 *
 * `decodeURIComponent` THROWS a URIError on a malformed escape — a bare `%`, or
 * a `%` not followed by two hex digits. Every caller here is decoding something
 * another process produced (a cookie, a `Content-Disposition` filename), so a
 * stray `%` is an input rather than a bug in this code, and an unguarded decode
 * kills the operation that was merely trying to read it: a ZIP export the
 * server has already produced, hashed and audited is reported as failed and
 * never offered (HUNT-029), or every mutating request loses its CSRF header.
 *
 * The raw text is the honest degradation — it is what was actually received,
 * and nothing here invents a substitute for it.
 */
export function percentDecodeOrRaw(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

/** Read the CSRF cookie set by the API, or null if absent. Canonical copy;
 * download/files/hashsets helpers import this rather than redefining it. */
export function csrfToken(): string | null {
  const match = document.cookie.match(/(?:^|;\s*)seance_csrf=([^;]*)/)
  return match ? percentDecodeOrRaw(match[1]) : null
}

export type QueryParams = Record<
  string,
  string | number | boolean | undefined | null
>

export interface ApiFetchOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE'
  body?: unknown
  query?: QueryParams
  signal?: AbortSignal
}

export async function apiFetch<T = unknown>(
  path: string,
  options: ApiFetchOptions = {},
): Promise<T> {
  const method = options.method ?? 'GET'
  let url = `${BASE}${path}`
  if (options.query) {
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(options.query)) {
      if (value !== undefined && value !== null) params.set(key, String(value))
    }
    const qs = params.toString()
    if (qs) url += `?${qs}`
  }

  const headers: Record<string, string> = {}
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (method !== 'GET') {
    const csrf = csrfToken()
    if (csrf) headers['x-csrf-token'] = csrf
  }
  if (options.body !== undefined) headers['Content-Type'] = 'application/json'

  const response = await fetch(url, {
    method,
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    signal: options.signal,
  })

  if (response.status === 204) return null as T

  if (!response.ok) {
    let code = 'UNKNOWN'
    let message = `Request failed with status ${response.status}`
    let details: unknown
    try {
      const payload = await response.json()
      if (payload?.error) {
        code = payload.error.code ?? code
        message = payload.error.message ?? message
        details = payload.error.details
      }
    } catch {
      // Non-JSON error body; keep defaults.
    }
    if (response.status === 401) notifyUnauthorized()
    throw new ApiRequestError(response.status, code, message, details)
  }

  return (await response.json()) as T
}

/** Build a same-origin URL for download links (exports, content streams). */
export function apiUrl(path: string, query?: QueryParams): string {
  let url = `${BASE}${path}`
  if (query) {
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null) params.set(key, String(value))
    }
    const qs = params.toString()
    if (qs) url += `?${qs}`
  }
  return url
}
