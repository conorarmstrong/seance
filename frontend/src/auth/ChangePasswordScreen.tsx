import { useState, type FormEvent } from 'react'
import { KeyRound, ShieldAlert } from 'lucide-react'
import { ApiRequestError } from '../api/http'
import { useAuth } from './AuthProvider'
import './login.css'

/// Shown full-screen when the session must rotate a default-seeded password
/// before it can do anything else (the server enforces this too).
///
/// Deliberately styled to look nothing like the login form: a large heading,
/// a "signed in as" confirmation, and an accent callout, so a returning user is
/// never left thinking their login just failed and the form reappeared.
export function ChangePasswordScreen() {
  const { session, changePassword, logout } = useAuth()
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    if (password !== confirm) {
      setError('Passwords do not match.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      await changePassword(password)
    } catch (err) {
      if (err instanceof ApiRequestError && err.status === 400) {
        setError('That password does not meet the requirements. Choose a stronger one.')
      } else {
        setError('Could not change the password. Try again.')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-screen">
      <form className="pwchange-card" onSubmit={onSubmit}>
        <div className="pwchange-header">
          <span className="pwchange-icon" aria-hidden="true">
            <KeyRound size={22} />
          </span>
          <div>
            <div className="pwchange-eyebrow">Séance · Account security</div>
            <h1 className="pwchange-title">Change your password</h1>
          </div>
        </div>

        <p className="pwchange-subtitle">
          You are signed in as <strong>{session?.username ?? 'your account'}</strong>. This is not
          the login screen.
        </p>

        <div className="pwchange-note" role="note">
          <ShieldAlert size={18} aria-hidden="true" />
          <span>
            This account is still using its default password. Set a new one to finish signing in.
            You will not be asked again.
          </span>
        </div>

        <label>
          New password
          <input
            type="password"
            autoFocus
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <label>
          Confirm new password
          <input
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </label>
        {error && (
          <p className="login-error" role="alert">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy || !password || !confirm}>
          {busy ? 'Updating…' : 'Update password and continue'}
        </button>
        <button type="button" className="pwchange-signout" onClick={logout}>
          Sign in as a different user
        </button>
      </form>
    </div>
  )
}
