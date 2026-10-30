import { useEffect } from 'react'
import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from '../auth/AuthProvider'
import { ChangePasswordScreen } from '../auth/ChangePasswordScreen'

export function RequireAuth() {
  const { session, authMode, requestAuthMode } = useAuth()
  const location = useLocation()

  // With no session, whether to redirect depends on whether the server actually
  // requires one, so ask. Held in an effect rather than in render so the
  // request is a side effect of needing the answer, not of drawing a frame.
  useEffect(() => {
    if (!session) requestAuthMode()
  }, [session, requestAuthMode])

  if (!session) {
    // The server may be running with SEANCE_AUTH_ENABLED=false, in which case
    // every route used to redirect to a login that cannot be completed and the
    // app was unusable in the mode the server advertises (LIVE-004).
    if (authMode === 'disabled') {
      return <Outlet />
    }
    // Not yet established. Neither state is asserted here: showing the login
    // screen would claim a sign-in is required before that is known, and
    // showing the app would claim it is not.
    if (authMode === 'unknown') {
      return (
        <div className="loading">Checking whether this server requires a sign-in…</div>
      )
    }
    return <Navigate to="/login" state={{ from: location.pathname }} replace />
  }
  // The server confines a default-seeded session to the password-change
  // endpoint; mirror that in the UI so the user is never stuck at a 403.
  if (session.mustChangePassword) {
    return <ChangePasswordScreen />
  }
  return <Outlet />
}
