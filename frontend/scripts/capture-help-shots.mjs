// Capture the help screenshots from a live, populated Séance instance.
//
// The help pages carry screenshots of the product. They go stale silently:
// nothing fails when the UI moves on and the images do not, and a reader
// trusts a picture more readily than prose. `memory-processes.png` was taken
// on 2026-07-31 and the memory pages changed three times after it.
//
// Chrome's own `--screenshot` fires on the load event, which for this app is
// before any data has arrived — it captures "Loading…". This waits for the
// content instead.
//
// Usage:
//   npm install --no-save playwright-core
//   node scripts/capture-help-shots.mjs <baseUrl> <caseId> <outDir>
//
// It needs a Séance server serving the built UI, with a case whose evidence has
// finished ingesting — the views it captures are the populated ones, and an
// empty view is worse documentation than a stale one.

import { mkdirSync } from 'node:fs'

// playwright-core is deliberately NOT a devDependency: it is 14 MB, this script
// runs a couple of times a year, and CI never runs it at all — so making every
// `npm ci` pay for it is the wrong trade. The cost of that choice is that the
// import can fail, so it fails with instructions rather than a stack trace.
let chromium
try {
  ;({ chromium } = await import('playwright-core'))
} catch {
  console.error(
    'This script needs playwright-core, which is not a dependency of this\n' +
      'package (see the note in the source). Install it just for this run:\n\n' +
      '    npm install --no-save playwright-core\n',
  )
  process.exit(2)
}

const [, , BASE, CASE_ID, OUT_DIR] = process.argv
if (!BASE || !CASE_ID || !OUT_DIR) {
  console.error('usage: capture-help-shots.mjs <baseUrl> <caseId> <outDir>')
  process.exit(2)
}
mkdirSync(OUT_DIR, { recursive: true })

/** Pages worth a picture, taken from the route tree in `src/app/routes.tsx`.
 *
 * The memory pages are nested under `memory/`, which the first version of this
 * script got wrong — and every wrong URL was reported as a success, because a
 * "Page not found" view has no loading state either. `isNotFound` below exists
 * because of that.
 */
const SHOTS = [
  // Memory tier. These are the ones that went stale: the screenshot predates
  // three changes to how these pages render.
  { file: 'memory-overview', path: 'memory' },
  { file: 'memory-image-profile', path: 'memory/image' },
  { file: 'memory-processes', path: 'memory/processes' },
  { file: 'memory-network', path: 'memory/network' },
  { file: 'memory-handles', path: 'memory/handles' },
  { file: 'memory-system', path: 'memory/system' },
  { file: 'memory-credentials', path: 'memory/credentials' },
  { file: 'memory-findings', path: 'memory/findings' },

  // The rest of the case views.
  { file: 'dashboard-overview', path: '' },
  { file: 'workbench', path: 'workbench' },
  { file: 'timeline-view', path: 'timeline' },
  { file: 'search-results', path: 'search' },
  { file: 'analysis-index', path: 'analysis' },
  { file: 'gallery', path: 'gallery' },
  { file: 'geo-map', path: 'geo' },
  { file: 'connections-graph', path: 'connections' },
  { file: 'execution', path: 'execution' },
  { file: 'system-info', path: 'system-info' },
  { file: 'duplicates', path: 'duplicates' },
  { file: 'communications', path: 'communications' },
  { file: 'entities', path: 'entities' },
  { file: 'bookmarks', path: 'bookmarks' },
  { file: 'filters', path: 'filters' },
  { file: 'hash-sets', path: 'hash-sets' },
  { file: 'audit-log', path: 'audit' },
  { file: 'case-settings', path: 'settings' },
  { file: 'help-page', path: 'help' },
]

const browser = await chromium.launch({
  executablePath: '/usr/bin/google-chrome',
  headless: true,
  args: ['--no-sandbox', '--disable-dev-shm-usage', '--hide-scrollbars'],
})
const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } })

let ok = 0
let loadingCount = 0
let missing = 0
let failed = 0
for (const shot of SHOTS) {
  const url = `${BASE}/cases/${CASE_ID}/${shot.path}`.replace(/\/$/, '')
  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
    // The app keeps a connection open, so `networkidle` never fires, and a
    // short fixed wait catches the skeleton placeholders rather than the rows.
    // Wait for the skeletons to go, then settle.
    await page.waitForTimeout(2000)
    try {
      await page.waitForFunction(
        () =>
          document.querySelectorAll(
            '[class*="skeleton" i], [aria-busy="true"], [class*="placeholder" i]',
          ).length === 0,
        { timeout: 25000 },
      )
    } catch {
      /* some pages legitimately keep a busy region; capture anyway */
    }
    await page.waitForTimeout(3000)

    // A wrong URL renders a perfectly clean page with no loading state, which
    // is exactly why the first run of this script reported 23 successes over
    // pages that did not exist. Check for the miss explicitly.
    const isNotFound = (await page.locator('text=/Page not found/i').count()) > 0
    const isLoading = (await page.locator('text=/^\\s*[Ll]oading/').count()) > 0

    if (isNotFound) {
      console.log(`  ✗ ${shot.file.padEnd(22)} route does not exist: ${url}`)
      missing += 1
      continue
    }

    await page.screenshot({ path: `${OUT_DIR}/${shot.file}.png` })
    if (isLoading) {
      console.log(`  ~ ${shot.file.padEnd(22)} captured while still loading`)
      loadingCount += 1
    } else {
      console.log(`  ✓ ${shot.file.padEnd(22)} ${shot.path || '(dashboard)'}`)
      ok += 1
    }
  } catch (err) {
    console.log(`  ✗ ${shot.file.padEnd(22)} ${err.message.split('\n')[0]}`)
    failed += 1
  }
}

await browser.close()
console.log(`\n${ok} captured, ${loadingCount} still loading, ${missing} missing route(s), ${failed} error(s), ${SHOTS.length} attempted`)
