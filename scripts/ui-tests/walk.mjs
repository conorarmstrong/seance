// Walk every case-level surface of Séance and screenshot it.
//   node walk.mjs <caseId> <outDir> [width]
import { open, login, writeReport, BASE } from './harness.mjs'

const [caseId, outDir, widthArg] = process.argv.slice(2)
if (!caseId || !outDir) {
  console.error('usage: node walk.mjs <caseId> <outDir> [width]')
  process.exit(2)
}
const width = Number(widthArg || 1440)

// Every surface an examiner can reach inside a case, in the order the left rail
// offers them, so the screenshots read as a tour rather than a pile.
const ROUTES = [
  ['overview', ''],
  ['timeline', '/timeline'],
  ['search', '/search?q=the'],
  ['search-unicode', '/search?q=%CE%B1'],
  ['analysis-index', '/analysis'],
  ['gallery', '/gallery'],
  ['geo', '/geo'],
  ['connections', '/connections'],
  ['execution', '/execution'],
  ['system-info', '/system-info'],
  ['duplicates', '/duplicates'],
  ['communications', '/communications'],
  ['entities', '/entities'],
  ['memory-image', '/memory/image'],
  ['memory-processes', '/memory/processes'],
  ['memory-network', '/memory/network'],
  ['memory-handles', '/memory/handles'],
  ['memory-system', '/memory/system'],
  ['memory-credentials', '/memory/credentials'],
  ['memory-findings', '/memory/findings'],
  ['bookmarks', '/bookmarks'],
  ['filters', '/filters'],
  ['hash-sets', '/hash-sets'],
  ['audit', '/audit'],
  ['settings', '/settings'],
  ['help', '/help'],
  ['not-found', '/no-such-screen'],
]

const { browser, page, shot, shots, problems } = await open({ outDir, width })

try {
  await login(page, shot)
  await shot('cases-list')

  for (const [name, sub] of ROUTES) {
    const url = `${BASE}/cases/${caseId}${sub}`
    try {
      await page.goto(url, { waitUntil: 'networkidle', timeout: 45000 })
    } catch {
      // networkidle can never settle on a page holding an SSE stream; the
      // screenshot is still worth taking, so fall back to a plain load.
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45000 }).catch(() => {})
    }
    await shot(name, { settle: 1400 })
    console.log('shot', name)
  }

  // The analysis viewer for whichever record types this case actually has —
  // an empty list here is itself a finding, so it is recorded either way.
  await page.goto(`${BASE}/cases/${caseId}/analysis`, { waitUntil: 'domcontentloaded' }).catch(() => {})
  await page.waitForTimeout(1500)
  const types = await page
    .locator('a[href*="/analysis/"]')
    .evaluateAll((els) => els.map((e) => e.getAttribute('href')).filter(Boolean).slice(0, 6))
    .catch(() => [])
  for (const href of types) {
    const name = `analysis-${href.split('/').pop().replace(/[^a-z0-9-]/gi, '')}`
    await page.goto(`${BASE}${href}`, { waitUntil: 'domcontentloaded' }).catch(() => {})
    await shot(name, { settle: 1400 })
    console.log('shot', name)
  }
} finally {
  const txt = writeReport(outDir, shots, problems)
  console.log('\n=== BROWSER COMPLAINTS ===')
  console.log(txt.slice(0, 6000))
  await browser.close()
}
