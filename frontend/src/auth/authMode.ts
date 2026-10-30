import { apiUrl } from '../api/http'

/**
 * Whether the server requires a login.
 *
 * `unknown` is a real state, not a placeholder: until the question is answered
 * the UI must neither sign the examiner in nor claim they are signed out. It
 * fails closed — anything that cannot positively establish "auth is off"
 * resolves to `enabled` and the login screen is shown exactly as before.
 */
export type AuthMode = 'unknown' | 'enabled' | 'disabled'

/** The subset of `GET /auth/me` this module reads. */
interface AuthMeResponse {
  /** Whether the credentials on this request were accepted. */
  authenticated?: boolean
  /**
   * Whether the server enforces authentication at all. Preferred over the
   * probe below when the server reports it; see `detectAuthMode`.
   */
  auth_enabled?: boolean
}

/**
 * A route that lives behind the auth middleware and is safe to call with no
 * credentials, no side effects, and no case context.
 */
const PROTECTED_PROBE = '/cases'

/**
 * Establish whether the server is running with `SEANCE_AUTH_ENABLED=false`.
 *
 * The server documents the flag and the API honours it — with auth off,
 * `GET /api/v1/cases` answers 200 to an unauthenticated request — but nothing
 * in the API states the mode, so the SPA redirected every route to `/login` and
 * the mode the server advertises was unusable (LIVE-004).
 *
 * Two ways to answer, in order of authority:
 *
 * 1. `auth_enabled` on `/auth/me`. A direct statement from the server. This key
 *    does not exist yet; the client reads it so that adding it server-side
 *    retires the probe below with no further client change.
 * 2. A protected route answering 200 to a request we have positively
 *    established carries no accepted credentials. `/auth/me` reads the same
 *    `Authorization` header and `seance_auth` cookie the middleware does, so
 *    `authenticated: false` means this browser holds nothing the server would
 *    accept. A 200 from a protected route after that can only mean the
 *    middleware is not enforcing anything.
 *
 * The order of those two steps is what keeps this safe. Probing first would
 * read a 200 that an HttpOnly session cookie earned — a cookie JS cannot see —
 * and present a real, attributable session as an anonymous one. So a browser
 * that IS authenticated (`authenticated: true`) is reported as `enabled`: the
 * session belongs in the normal signed-in flow, not here.
 *
 * Every other outcome — a non-OK `/auth/me`, unparseable JSON, a network
 * failure, a 401 or 403 or 500 from the probe — returns `enabled`. Absence of
 * evidence that auth is off is not evidence that auth is off.
 */
export async function detectAuthMode(signal?: AbortSignal): Promise<AuthMode> {
  let me: AuthMeResponse
  try {
    const response = await fetch(apiUrl('/auth/me'), { signal })
    if (!response.ok) return 'enabled'
    me = (await response.json()) as AuthMeResponse
  } catch {
    return 'enabled'
  }

  if (typeof me?.auth_enabled === 'boolean') {
    return me.auth_enabled ? 'enabled' : 'disabled'
  }

  // Anything other than an explicit "no credentials were accepted" leaves the
  // probe unreadable, so it is not run.
  if (me?.authenticated !== false) return 'enabled'

  try {
    const probe = await fetch(apiUrl(PROTECTED_PROBE), { signal })
    return probe.status === 200 ? 'disabled' : 'enabled'
  } catch {
    return 'enabled'
  }
}
