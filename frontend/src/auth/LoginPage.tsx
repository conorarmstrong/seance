import { useEffect, useState, type FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { ApiRequestError } from '../api/http'
import { useAuth } from './AuthProvider'
import './login.css'

export function LoginPage() {
  const { session, authMode, requestAuthMode, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const from = (location.state as { from?: string } | null)?.from ?? '/'

  // A server started with SEANCE_AUTH_ENABLED=false has no credentials to
  // check, so this form is a dead end on it (LIVE-004). Ask which mode the
  // server is in; the form stays usable meanwhile, and only a positive
  // "disabled" sends the examiner on.
  useEffect(() => {
    if (!session) requestAuthMode()
  }, [session, requestAuthMode])

  // Already signed in: redirect declaratively (navigating during render trips a
  // React state-update warning and is flaky under StrictMode).
  if (session) {
    return <Navigate to={from} replace />
  }
  if (authMode === 'disabled') {
    return <Navigate to={from} replace />
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(username, password)
      navigate(from, { replace: true })
    } catch (err) {
      if (err instanceof ApiRequestError && err.status === 401) {
        setError('Invalid username or password.')
      } else if (err instanceof ApiRequestError && err.status === 429) {
        setError('Too many attempts. Wait a minute and try again.')
      } else {
        setError('Could not reach the server. Check that it is running.')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={onSubmit}>
        <h1 className="login-wordmark">SÉANCE</h1>
        <p className="login-tagline">Digital forensics workbench</p>
        <label htmlFor="login-username">
          Username
          <input
            id="login-username"
            name="username"
            type="text"
            autoFocus
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>
        <label htmlFor="login-password">
          Password
          <input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {error && (
          <p className="login-error" role="alert">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy || !username || !password}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
