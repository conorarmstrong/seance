import { useEffect, useState } from 'react'

/** How often to re-check for a newer frontend build. */
const POLL_MS = 45_000

/**
 * Pull the content-hashed bundle filename (e.g. `index-a-kAveA-.js`) out of a
 * URL or HTML snippet, or null if none is present.
 */
export function extractBundleId(text: string | null): string | null {
  if (!text) return null
  const match = text.match(/index-[A-Za-z0-9_-]+\.js/)
  return match ? match[0] : null
}

/**
 * The bundle this tab is currently running, read from the module script Vite
 * injects into index.html. Null under the dev server or in tests (no such
 * tag), where the version check is a no-op.
 */
function runningBundleId(): string | null {
  const el = document.querySelector(
    'script[type="module"][src*="/assets/index-"]',
  )
  return extractBundleId(el?.getAttribute('src') ?? null)
}

/**
 * The bundle the server is serving right now. index.html is sent `no-cache`,
 * so this reflects the latest build. Returns null on any failure so a
 * transient network blip never nags the user.
 */
async function servedBundleId(): Promise<string | null> {
  try {
    const res = await fetch('/index.html', { cache: 'no-store' })
    if (!res.ok) return null
    return extractBundleId(await res.text())
  } catch {
    return null
  }
}

/**
 * True once the server is serving a newer frontend build than the one this tab
 * loaded. Checks on mount, every minute, and whenever the tab regains focus.
 * Stays a no-op when the running bundle can't be identified (dev server /
 * tests), so it never fires spuriously.
 */
export function useVersionCheck(): boolean {
  const [outdated, setOutdated] = useState(false)

  useEffect(() => {
    const running = runningBundleId()
    if (!running) return

    let disposed = false
    const check = async () => {
      if (disposed) return
      const served = await servedBundleId()
      if (!disposed && served && served !== running) setOutdated(true)
    }

    // Check on mount and whenever the tab regains focus (the user is present).
    // The background interval skips while the tab is hidden — a backgrounded
    // tab needn't keep polling.
    void check()
    const onFocus = () => void check()
    const timer = setInterval(() => {
      if (!document.hidden) void check()
    }, POLL_MS)
    window.addEventListener('focus', onFocus)

    return () => {
      disposed = true
      clearInterval(timer)
      window.removeEventListener('focus', onFocus)
    }
  }, [])

  return outdated
}
