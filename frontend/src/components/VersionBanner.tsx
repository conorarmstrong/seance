import { useState } from 'react'
import { RefreshCw, X } from 'lucide-react'
import { useVersionCheck } from '../hooks/useVersionCheck'
import './version-banner.css'

/**
 * Floating prompt shown when the server is serving a newer frontend build than
 * this long-lived tab loaded. Single-page navigation never re-fetches the JS,
 * so without this a tab can run stale code indefinitely.
 */
export function VersionBanner() {
  const outdated = useVersionCheck()
  const [dismissed, setDismissed] = useState(false)
  if (!outdated || dismissed) return null

  return (
    <div className="version-banner" role="alert">
      <span className="version-banner-text">A new version is available.</span>
      <button
        type="button"
        className="version-banner-reload"
        onClick={() => window.location.reload()}
      >
        <RefreshCw size={13} aria-hidden="true" /> Reload
      </button>
      <button
        type="button"
        className="version-banner-dismiss"
        aria-label="Dismiss"
        onClick={() => setDismissed(true)}
      >
        <X size={14} aria-hidden="true" />
      </button>
    </div>
  )
}
