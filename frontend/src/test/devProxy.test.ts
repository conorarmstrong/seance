// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
/// <reference types="node" />
// This test reads the package's own config and README (node fs/path); the
// reference pulls in Node typings for this file only, since the app tsconfig is
// DOM-scoped.
import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * Guard on the one line that makes the SPA and the API same-origin during
 * development. Auth cookies and the SSE stream both depend on `/api` being
 * proxied to the running server; pointed at a port nothing is listening on,
 * every request fails as a proxy error that reads like a broken backend rather
 * than a broken config — and a one-character edit to that line has reached the
 * working tree before.
 *
 * 8080 is the API default in both places it is set (`SEANCE_BIND` in
 * seance_api, `--port` in seance_cli) and it is what this package's README
 * tells operators to expect, so moving the proxy means moving those with it.
 */

/** Walk up from the working directory to the frontend package root. */
function findFrontendRoot(): string {
  let dir = process.cwd()
  for (let i = 0; i < 8; i++) {
    if (
      fs.existsSync(path.join(dir, 'vite.config.ts')) &&
      fs.existsSync(path.join(dir, 'src'))
    ) {
      return dir
    }
    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  throw new Error('could not locate the frontend root (no vite.config.ts)')
}

const frontendRoot = findFrontendRoot()
const configSrc = fs.readFileSync(
  path.join(frontendRoot, 'vite.config.ts'),
  'utf8',
)
const readmeSrc = fs.readFileSync(path.join(frontendRoot, 'README.md'), 'utf8')

/** The port the dev server forwards `/api` to. */
function proxyTargetPort(): string {
  const match = configSrc.match(
    /'\/api':\s*\{\s*target:\s*'http:\/\/127\.0\.0\.1:(\d+)'/,
  )
  if (!match) throw new Error('no /api proxy target found in vite.config.ts')
  return match[1]
}

describe('dev server API proxy', () => {
  it('forwards /api to the port the API binds by default', () => {
    expect(proxyTargetPort()).toBe('8080')
  })

  it('forwards /api to the port the README tells operators to run', () => {
    const documented = readmeSrc.match(
      /proxies `\/api` to `http:\/\/127\.0\.0\.1:(\d+)`/,
    )
    expect(
      documented,
      'README no longer documents the dev proxy target',
    ).not.toBeNull()
    expect(proxyTargetPort()).toBe(documented![1])
  })
})
