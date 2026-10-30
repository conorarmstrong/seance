// Séance UI walkthrough harness.
//
// Drives a local Chromium against a running Séance instance, screenshots every
// surface, and records what the browser complained about while it did. The
// screenshots are the deliverable; the console/network log is the evidence that
// a screen which LOOKS fine was not quietly failing underneath.
import { chromium } from 'playwright-core'
import fs from 'node:fs'
import path from 'node:path'

const CHROME =
  process.env.SEANCE_CHROME ||
  `${process.env.HOME}/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome`

export const BASE = process.env.SEANCE_BASE || 'http://127.0.0.1:8899'
export const USER = process.env.SEANCE_USER || 'admin'
// No default: a committed test harness must not carry a credential, even a
// throwaway one. The runner supplies it (see documentation/UI_TESTING.md §8).
export const PASS = process.env.SEANCE_PASS
if (!PASS) {
  throw new Error('SEANCE_PASS is not set — export the admin password of the instance under test')
}

export async function open({ outDir, width = 1440, height = 900 }) {
  fs.mkdirSync(outDir, { recursive: true })
  const browser = await chromium.launch({
    executablePath: CHROME,
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--force-color-profile=srgb'],
  })
  const context = await browser.newContext({
    viewport: { width, height },
    deviceScaleFactor: 1,
    // A forensic workstation is a desktop; test what an examiner actually sees.
    colorScheme: 'dark',
  })
  const page = await context.newPage()

  // Everything the browser objected to, kept per-shot so a complaint can be
  // attributed to the screen that caused it.
  const problems = []
  let bucket = 'startup'
  page.on('console', (m) => {
    if (m.type() === 'error' || m.type() === 'warning') {
      problems.push({ where: bucket, kind: `console.${m.type()}`, text: m.text().slice(0, 500) })
    }
  })
  page.on('pageerror', (e) => {
    problems.push({ where: bucket, kind: 'pageerror', text: String(e).slice(0, 500) })
  })
  page.on('requestfailed', (r) => {
    problems.push({
      where: bucket,
      kind: 'requestfailed',
      text: `${r.method()} ${r.url()} — ${r.failure()?.errorText}`.slice(0, 500),
    })
  })
  page.on('response', (r) => {
    if (r.status() >= 400) {
      problems.push({ where: bucket, kind: `http.${r.status()}`, text: `${r.request().method()} ${r.url()}`.slice(0, 500) })
    }
  })

  const shots = []
  async function shot(name, opts = {}) {
    bucket = name
    await page.waitForTimeout(opts.settle ?? 700)
    const file = path.join(outDir, `${String(shots.length).padStart(2, '0')}-${name}.png`)
    await page.screenshot({ path: file, fullPage: opts.fullPage ?? true, animations: 'disabled' })
    shots.push({ name, file })
    return file
  }

  return { browser, context, page, shot, shots, problems, setBucket: (b) => (bucket = b) }
}

/** Log in through the real form, so the login screen is exercised too. */
export async function login(page, shot) {
  await page.goto(`${BASE}/`, { waitUntil: 'domcontentloaded' })
  // The SPA bundle has to execute before there is a form to fill; waiting for
  // the field itself rather than a timeout keeps this from depending on how
  // busy the machine is.
  await page
    .locator('input[type="password"]')
    .first()
    .waitFor({ state: 'visible', timeout: 30000 })
    .catch(() => {})
  if (shot) await shot('login')
  if (!page.url().includes('/login')) return // already authenticated

  // NOT input[type="text"]: the username field carries no explicit type
  // attribute (nor name/id), so an attribute selector never matches it.
  await page.locator('input:not([type="password"])').first().fill(USER)
  await page.locator('input[type="password"]').first().fill(PASS)
  await page.locator('button[type="submit"]').first().click()

  // A login that silently fails would make every later screenshot a picture of
  // the login form, which is the failure this walk suffered the first time.
  // Wait for the app to leave /login and refuse to continue if it does not.
  try {
    await page.waitForFunction(() => !location.pathname.startsWith('/login'), null, { timeout: 20000 })
  } catch {
    const msg = await page.locator('body').innerText().catch(() => '')
    throw new Error(`login did not complete; screen said: ${msg.replace(/\s+/g, ' ').slice(0, 300)}`)
  }
  await page.waitForTimeout(1500)
}

export function writeReport(outDir, shots, problems) {
  const report = { shots: shots.map((s) => s.name), problems }
  fs.writeFileSync(path.join(outDir, 'problems.json'), JSON.stringify(report, null, 2))
  const byWhere = {}
  for (const p of problems) (byWhere[p.where] ||= []).push(p)
  let txt = ''
  for (const [where, list] of Object.entries(byWhere)) {
    txt += `\n## ${where}  (${list.length})\n`
    const seen = new Set()
    for (const p of list) {
      const key = `${p.kind}|${p.text}`
      if (seen.has(key)) continue
      seen.add(key)
      txt += `  [${p.kind}] ${p.text}\n`
    }
  }
  fs.writeFileSync(path.join(outDir, 'problems.txt'), txt || 'none\n')
  return txt
}
