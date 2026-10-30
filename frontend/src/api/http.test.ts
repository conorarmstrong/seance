import { http, HttpResponse } from 'msw'
import { afterEach, describe, expect, it } from 'vitest'
import { server } from '../test/server'
import {
  ApiRequestError,
  apiFetch,
  clearToken,
  onUnauthorized,
  setToken,
} from './http'

afterEach(() => {
  clearToken()
  document.cookie = 'seance_csrf=; Max-Age=0; path=/'
})

describe('apiFetch', () => {
  it('parses JSON responses', async () => {
    server.use(
      http.get('/api/v1/version', () =>
        HttpResponse.json({ version: '1.0.0', name: 'seance' }),
      ),
    )
    const result = await apiFetch<{ version: string }>('/version')
    expect(result.version).toBe('1.0.0')
  })

  it('attaches the bearer token when set', async () => {
    let seen: string | null = null
    server.use(
      http.get('/api/v1/status', ({ request }) => {
        seen = request.headers.get('authorization')
        return HttpResponse.json({ active_tasks: 0 })
      }),
    )
    setToken('tok123')
    await apiFetch('/status')
    expect(seen).toBe('Bearer tok123')
  })

  it('sends the CSRF cookie value as a header on mutations', async () => {
    let seen: string | null = null
    server.use(
      http.post('/api/v1/cases', ({ request }) => {
        seen = request.headers.get('x-csrf-token')
        return HttpResponse.json({ id: 'x' })
      }),
    )
    document.cookie = 'seance_csrf=csrf-abc; path=/'
    await apiFetch('/cases', { method: 'POST', body: { name: 'Case' } })
    expect(seen).toBe('csrf-abc')
  })

  it('keeps sending mutations when the CSRF cookie is not valid percent-encoding', async () => {
    // decodeURIComponent THROWS on a malformed escape, and this value is set by
    // another process, so a stray `%` is an input rather than a bug here. An
    // unguarded decode took out every mutating request in the app — the same
    // class as the export whose download it cost (HUNT-029). Undecodable is
    // handed on exactly as received; the server then judges the token.
    let seen: string | null = null
    server.use(
      http.post('/api/v1/cases', ({ request }) => {
        seen = request.headers.get('x-csrf-token')
        return HttpResponse.json({ id: 'x' })
      }),
    )
    document.cookie = 'seance_csrf=50%_recovered; path=/'
    await apiFetch('/cases', { method: 'POST', body: { name: 'Case' } })
    expect(seen).toBe('50%_recovered')
  })

  it('throws ApiRequestError with the server error code', async () => {
    server.use(
      http.get('/api/v1/cases/bad', () =>
        HttpResponse.json(
          {
            error: { code: 'RESOURCE_NOT_FOUND', message: 'Case not found' },
          },
          { status: 404 },
        ),
      ),
    )
    const err = (await apiFetch('/cases/bad').catch(
      (e) => e,
    )) as ApiRequestError
    expect(err).toBeInstanceOf(ApiRequestError)
    expect(err.code).toBe('RESOURCE_NOT_FOUND')
    expect(err.status).toBe(404)
    expect(err.message).toBe('Case not found')
  })

  it('returns null for 204 No Content', async () => {
    server.use(
      http.delete('/api/v1/cases/abc', () =>
        new HttpResponse(null, { status: 204 }),
      ),
    )
    const result = await apiFetch('/cases/abc', { method: 'DELETE' })
    expect(result).toBeNull()
  })

  it('serializes query params, skipping undefined', async () => {
    let url = ''
    server.use(
      http.get('/api/v1/cases/1/timeline', ({ request }) => {
        url = request.url
        return HttpResponse.json({ events: [] })
      }),
    )
    await apiFetch('/cases/1/timeline', {
      query: { page: 2, search: 'evil.exe', modules: undefined },
    })
    const parsed = new URL(url)
    expect(parsed.searchParams.get('page')).toBe('2')
    expect(parsed.searchParams.get('search')).toBe('evil.exe')
    expect(parsed.searchParams.has('modules')).toBe(false)
  })

  it('notifies listeners on 401 so the app can force re-login', async () => {
    server.use(
      http.get('/api/v1/status', () =>
        HttpResponse.json(
          { error: { code: 'INVALID_TOKEN', message: 'expired' } },
          { status: 401 },
        ),
      ),
    )
    let fired = false
    const off = onUnauthorized(() => {
      fired = true
    })
    await apiFetch('/status').catch(() => {})
    off()
    expect(fired).toBe(true)
  })
})
