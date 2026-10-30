import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import {
  ApiRequestError,
  apiFetch,
  clearToken,
  onUnauthorized,
  setToken,
} from '../api/http'
import { useToast } from '../components/toast/ToastProvider'
import type { LoginResponse } from '../api/types'
import { detectAuthMode, type AuthMode } from './authMode'

/**
 * Where the non-secret session metadata lives.
 *
 * Exported so other code can ask *whether there is a session* without importing
 * the auth context — which `ThemeProvider` cannot do, since it wraps this
 * provider in order to paint before anything else renders.
 */
export const SESSION_KEY = 'seance_session'

export interface Session {
  token: string
  username: string
  role: string
  expires_at: number
  /// The server requires this session to change its password before anything else.
  mustChangePassword: boolean
  /// The user's id, used to target the password-change endpoint.
  userId: string | null
}

/**
 * Persist only non-secret session metadata. The JWT is deliberately NOT stored
 * (BUG-200): the HttpOnly `seance_auth` cookie authenticates same-origin
 * requests, so the token only needs to live in memory for the active tab. This
 * also scrubs any JWT an older build wrote into this record.
 */
function persistSession(session: Session): void {
  localStorage.setItem(SESSION_KEY, JSON.stringify({ ...session, token: '' }))
}

interface AuthContextValue {
  session: Session | null
  /**
   * Whether the server requires a login. `unknown` until something asks; see
   * `requestAuthMode`.
   */
  authMode: AuthMode
  /**
   * Ask for the server's auth mode. Idempotent, and deliberately opt-in: the
   * question only matters where a missing session would otherwise be turned
   * away, so nothing is spent on it while a session is in hand.
   */
  requestAuthMode: () => void
  login: (username: string, password: string) => Promise<void>
  changePassword: (newPassword: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

/**
 * The context itself, for tests that need to drive a session directly.
 *
 * Exported for one reason and it is worth stating: `ThemeProvider`'s reconcile
 * has to re-ask when the identity changes, and the only way to prove it does is
 * to change the identity **without remounting** — a remount re-runs a
 * mount-scoped effect too, so a test that remounted would pass against the very
 * defect it exists for. Not for production use; `useAuth` is the way in.
 */
export const AuthContextForTests = AuthContext

function loadStoredSession(): Session | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY)
    if (!raw) {
      // No session record: clear any orphaned seance_token too, otherwise
      // getToken() keeps attaching a stale JWT while the UI is logged-out
      // (BUG-173).
      clearToken()
      return null
    }
    const session = JSON.parse(raw) as Session
    if (session.expires_at * 1000 <= Date.now()) {
      // Drop any legacy token too, not just the session record: leaving
      // seance_token in localStorage lets getToken() keep handing out an expired
      // JWT while the UI shows logged-out.
      clearToken()
      localStorage.removeItem(SESSION_KEY)
      return null
    }
    // The JWT is no longer restored to memory (BUG-200); same-origin cookie auth
    // carries requests across a reload. Scrub any token an older build persisted
    // here and clear any legacy seance_token key.
    session.token = ''
    persistSession(session)
    clearToken()
    return session
  } catch {
    // Corrupt session JSON: clear the token as well so no stale JWT survives.
    clearToken()
    localStorage.removeItem(SESSION_KEY)
    return null
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const toast = useToast()
  const [session, setSession] = useState<Session | null>(loadStoredSession)
  const [authMode, setAuthMode] = useState<AuthMode>('unknown')
  const [authModeWanted, setAuthModeWanted] = useState(false)
  const requestAuthMode = useCallback(() => setAuthModeWanted(true), [])

  const clearSession = useCallback(() => {
    clearToken()
    localStorage.removeItem(SESSION_KEY)
    setSession(null)
  }, [])

  // Guards against re-entry: if the logout POST itself ever answered 401 its
  // listener would call back in here and loop.
  const logoutInFlight = useRef(false)

  const logout = useCallback(() => {
    // Local state clears regardless: this browser IS signed out either way.
    // What must not be swallowed is the server saying it could not revoke the
    // token. `CR-028` made the server answer 500 REVOCATION_FAILED for that,
    // and this `.catch(() => {})` threw the answer away — the examiner saw the
    // login screen while their token stayed valid for the rest of its life,
    // which is the SEC-001 gap with a better error message behind it.
    if (!logoutInFlight.current) {
      logoutInFlight.current = true
      apiFetch('/auth/logout', { method: 'POST' })
        .catch((err: unknown) => {
          if (err instanceof ApiRequestError && err.code === 'REVOCATION_FAILED') {
            toast.error(err.message)
          }
        })
        .finally(() => {
          logoutInFlight.current = false
        })
    }
    clearSession()
  }, [clearSession, toast])

  const login = useCallback(async (username: string, password: string) => {
    // Login is CSRF-protected; a prior GET seeds the csrf cookie.
    await apiFetch('/auth/me').catch(() => {})
    const response = await apiFetch<LoginResponse>('/auth/login', {
      method: 'POST',
      body: { username, password },
    })
    const next: Session = {
      token: response.token,
      username: response.username,
      role: response.role,
      expires_at: response.expires_at,
      mustChangePassword: response.must_change_password ?? false,
      userId: response.user_id ?? null,
    }
    setToken(next.token)
    persistSession(next)
    setSession(next)
  }, [])

  const changePassword = useCallback(
    async (newPassword: string) => {
      if (!session?.userId) throw new Error('No active user to change the password for')
      // The must-change token may only reach the /password endpoint.
      await apiFetch(`/users/${session.userId}/password`, {
        method: 'POST',
        body: { password: newPassword },
      })
      // The current token still carries the must-change claim; re-login with the
      // new password to mint a clean, full-access token.
      await login(session.username, newPassword)
    },
    [session, login],
  )

  // A 401 tears the session down the same way an explicit logout does. Clearing
  // only local state left the HttpOnly `seance_auth` cookie in the browser, so
  // same-origin requests kept authenticating (and a re-login in another tab, or
  // a password rotation, could leave the UI logged-out while the cookie stayed
  // valid until its own max-age). BUG-235.
  useEffect(() => {
    return onUnauthorized(logout)
  }, [logout])

  // Cold load discards an already-expired session; this clears one that expires
  // while a long-lived tab stays open, rather than waiting for the next 401.
  // A timer fires at expiry (skipped past setTimeout's ~24.8-day ceiling) and a
  // focus check catches expiry that elapsed while the tab was backgrounded.
  // Expiry goes through logout (not a bare clearSession) so the server cookie is
  // cleared too; otherwise same-origin cookie auth keeps working until the
  // cookie's own max-age even though the UI shows logged-out.
  useEffect(() => {
    if (!session) return
    const msUntilExpiry = session.expires_at * 1000 - Date.now()
    if (msUntilExpiry <= 0) {
      logout()
      return
    }
    const onFocus = () => {
      if (session.expires_at * 1000 <= Date.now()) logout()
    }
    window.addEventListener('focus', onFocus)
    const timer =
      msUntilExpiry < 2 ** 31 ? setTimeout(() => logout(), msUntilExpiry) : undefined
    return () => {
      window.removeEventListener('focus', onFocus)
      if (timer !== undefined) clearTimeout(timer)
    }
  }, [session, logout])

  // Learn whether the server runs with SEANCE_AUTH_ENABLED=false (LIVE-004).
  // Only asked once someone needs the answer, and never while a session is
  // held: a signed-in examiner is already past every gate the answer governs.
  // Re-run on sign-out so a server whose mode changed under a long-lived tab is
  // re-read rather than assumed.
  useEffect(() => {
    if (!authModeWanted || session) return
    let cancelled = false
    const controller = new AbortController()
    setAuthMode('unknown')
    detectAuthMode(controller.signal).then(
      (mode) => {
        if (!cancelled) setAuthMode(mode)
      },
      () => {
        // detectAuthMode resolves rather than rejects, but a rejection here
        // must still land closed rather than leaving the UI mid-decision.
        if (!cancelled) setAuthMode('enabled')
      },
    )
    return () => {
      cancelled = true
      controller.abort()
    }
  }, [authModeWanted, session])

  const value = useMemo(
    () => ({ session, authMode, requestAuthMode, login, changePassword, logout }),
    [session, authMode, requestAuthMode, login, changePassword, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
