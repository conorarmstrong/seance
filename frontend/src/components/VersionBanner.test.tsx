import { fireEvent, render, screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { afterEach, describe, expect, it } from 'vitest'
import { server } from '../test/server'
import { VersionBanner } from './VersionBanner'

// Simulate the module script Vite injects into index.html, so the hook can
// read which bundle this "tab" is running.
function setRunningBundle(id: string | null) {
  document
    .querySelectorAll('script[data-test-bundle]')
    .forEach((n) => n.remove())
  if (id) {
    const s = document.createElement('script')
    s.type = 'module'
    s.src = `/assets/${id}`
    s.setAttribute('data-test-bundle', 'true')
    document.head.appendChild(s)
  }
}

function serveIndexWith(bundle: string) {
  server.use(
    http.get('/index.html', () =>
      HttpResponse.text(
        `<!doctype html><script type="module" src="/assets/${bundle}"></script>`,
      ),
    ),
  )
}

const tick = () => new Promise((r) => setTimeout(r, 40))

afterEach(() => setRunningBundle(null))

describe('VersionBanner', () => {
  it('prompts to reload when the served bundle hash changes', async () => {
    setRunningBundle('index-OLD000.js')
    serveIndexWith('index-NEW111.js')

    render(<VersionBanner />)

    expect(
      await screen.findByRole('button', { name: /reload/i }),
    ).toBeInTheDocument()
    expect(screen.getByText(/new version is available/i)).toBeInTheDocument()
  })

  it('stays hidden when the served bundle matches the running one', async () => {
    setRunningBundle('index-SAME00.js')
    serveIndexWith('index-SAME00.js')

    render(<VersionBanner />)
    await tick()

    expect(
      screen.queryByRole('button', { name: /reload/i }),
    ).not.toBeInTheDocument()
  })

  it('is a no-op when the running bundle cannot be identified', async () => {
    // No <script> tag and no /index.html handler: the hook must not fetch at
    // all (an unhandled request would error under onUnhandledRequest:'error').
    setRunningBundle(null)

    render(<VersionBanner />)
    await tick()

    expect(
      screen.queryByRole('button', { name: /reload/i }),
    ).not.toBeInTheDocument()
  })

  it('can be dismissed', async () => {
    setRunningBundle('index-OLD000.js')
    serveIndexWith('index-NEW111.js')

    render(<VersionBanner />)
    await screen.findByRole('button', { name: /reload/i })

    fireEvent.click(screen.getByRole('button', { name: /dismiss/i }))

    expect(
      screen.queryByRole('button', { name: /reload/i }),
    ).not.toBeInTheDocument()
  })
})
