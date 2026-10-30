// Interaction pass — dimension B of documentation/UI_TESTING.md.
//
// Route coverage proves a screen RENDERS. This drives its controls and then
// asserts the forensic-honesty invariants (dimension J) against what the screen
// actually says afterwards. Every check is written as a question with a
// defensible answer, because a failure here is a claim about the product, not a
// broken selector: each records the text it judged so a human can disagree.
//
//   node interact.mjs <caseId> <outDir> [memoryCaseId]
import { open, login, BASE } from './harness.mjs'
import fs from 'node:fs'
import path from 'node:path'

const [caseId, outDir, memoryCaseId] = process.argv.slice(2)
const findings = []
const checks = []

function record(ok, screen, name, detail) {
  checks.push({ ok, screen, name, detail })
  if (!ok) findings.push({ screen, name, detail })
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${screen} :: ${name}${ok ? '' : ` — ${detail}`}`)
}

const norm = (s) => (s || '').replace(/\s+/g, ' ').trim()

const { browser, page, shot, problems } = await open({ outDir, width: 1440, height: 900 })

async function go(sub, settle = 2200) {
  await page.goto(`${BASE}${sub}`, { waitUntil: 'domcontentloaded' }).catch(() => {})
  await page.waitForTimeout(settle)
}
const bodyText = async () => norm(await page.locator('body').innerText().catch(() => ''))

/** Click the first control matching `name`; returns whether it was found. */
async function click(role, name, settle = 1600) {
  const el = page.getByRole(role, { name }).first()
  if (!(await el.count())) return false
  await el.click({ timeout: 5000 }).catch(() => {})
  await page.waitForTimeout(settle)
  return true
}

try {
  await login(page)

  // ---- Timeline: the two chart modes route coverage never opened -----------
  await go(`/cases/${caseId}/timeline`)
  const tlBase = await bodyText()
  record(/\d/.test(tlBase), 'timeline', 'renders an event count', tlBase.slice(0, 120))

  for (const mode of ['Swimlanes', 'Heatmap', 'Activity']) {
    const found = await click('button', mode, 2000)
    record(found, 'timeline', `mode "${mode}" is reachable`, found ? '' : 'no such control')
    if (found) {
      await shot(`timeline-${mode.toLowerCase()}`, { settle: 900, fullPage: false })
      const t = await bodyText()
      // A view that silently shows nothing is the failure mode these modes have:
      // an empty swimlane reads as "no activity", which is a claim.
      const blank = t.length < 400
      record(!blank, 'timeline', `mode "${mode}" is not silently blank`, blank ? t.slice(0, 200) : '')
    }
  }

  // ---- Search: the refusal path, and that it names a route that reaches ----
  await go(`/cases/${caseId}/search?q=the`, 2600)
  const sBase = await bodyText()
  record(/match|result|Showing/i.test(sBase), 'search', 'states what it matched', sBase.slice(0, 140))
  // Honesty: a count on this screen must carry its population or a floor marker.
  const floorish = /of\s+[\d,]+|at least|floor|no page number/i.test(sBase)
  record(floorish, 'search', 'a stated count carries its population', sBase.slice(0, 200))

  // Deep jump past the ceiling must be REFUSED with the route that reaches.
  await go(`/cases/${caseId}/search?q=the&offset=100001`, 2600)
  const sDeep = await bodyText()
  const refused = /cannot|refus|ceiling|past this server/i.test(sDeep)
  record(refused, 'search', 'a jump past the ceiling is refused, not served empty', sDeep.slice(0, 220))
  if (refused) {
    const namesRoute = /cursor|export|Next|first page/i.test(sDeep)
    record(namesRoute, 'search', 'the refusal names a route that does reach', sDeep.slice(0, 260))
  }

  // ---- Gallery: safe view defaults OFF, and the choice must survive -------
  // The default changed on 2026-09-07 (UI-025). What is asserted here is not
  // the default on its own but the pair: OFF by default, and ON *sticks*.
  // While it defaulted ON, forgetting the toggle merely re-protected you; now
  // an examiner who turns it on and moves to another case would be shown an
  // unblurred grid of exactly what the control exists to hide, so persistence
  // is the safeguard and belongs in the browser-driven layer, not only in a
  // unit test with a mocked localStorage.
  await go(`/cases/${caseId}/gallery`, 3200)
  const g = await bodyText()
  const safeOff = /safe view:?\s*off/i.test(g)
  record(safeOff, 'gallery', 'safe view defaults OFF', g.slice(0, 160))

  const safeToggle = page.locator('button.gl-safe-toggle').first()
  if (await safeToggle.count()) {
    await safeToggle.click().catch(() => {})
    await page.waitForTimeout(200)
    const afterClick = await bodyText()
    record(/safe view:?\s*on/i.test(afterClick), 'gallery', 'safe view turns on', afterClick.slice(0, 160))

    await go(`/cases/${caseId}/gallery`, 2400)
    const afterReload = await bodyText()
    record(/safe view:?\s*on/i.test(afterReload), 'gallery',
      'safe view stays on across a reload', afterReload.slice(0, 160))

    // Leave the browser as it was found, so a later run starts from the default.
    const back = page.locator('button.gl-safe-toggle').first()
    if (await back.count()) await back.click().catch(() => {})
  } else {
    record(false, 'gallery', 'safe view toggle is present', 'button.gl-safe-toggle not found')
  }
  await shot('gallery-loaded', { settle: 900, fullPage: false })
  // The gallery was never seen populated in the route walk; say which it is.
  const galleryState = /no (images|pictures)|nothing/i.test(g)
    ? 'empty state'
    : /loading/i.test(g)
      ? 'STILL LOADING after 3.2s'
      : 'populated'
  record(galleryState !== 'STILL LOADING after 3.2s', 'gallery', 'finishes loading within 3.2s', galleryState)

  // ---- Analysis: every card opens, and none is labelled with a bare number -
  await go(`/cases/${caseId}/analysis`, 2600)
  const cardTypes = await page
    .locator('a[href*="/analysis/"]')
    .evaluateAll((els) => els.map((e) => e.getAttribute('href').split('/').pop()).filter(Boolean))
    .catch(() => [])
  record(cardTypes.length > 0, 'analysis', 'lists record types', `${cardTypes.length} types`)
  const numericLabel = cardTypes.filter((t) => /^\d+$/.test(decodeURIComponent(t)))
  record(numericLabel.length === 0, 'analysis', 'no type is labelled with a bare number',
    numericLabel.join(',') || '')

  // Open each type and require it to render rows or an honest empty state.
  for (const t of cardTypes.slice(0, 8)) {
    await go(`/cases/${caseId}/analysis/${t}`, 2400)
    const v = await bodyText()
    const decoded = decodeURIComponent(t)
    const hasRows = (await page.locator('table tbody tr').count().catch(() => 0)) > 0
    const honestEmpty = /no |none|nothing/i.test(v)
    record(hasRows || honestEmpty, 'analysis', `viewer "${decoded}" shows rows or says why not`,
      v.slice(0, 160))
    // Honesty: a viewer showing FEWER rows than it says exist must disclose that
    // it is a slice. A viewer showing all of them states the total and is
    // complete — demanding slice language there would be demanding a falsehood.
    if (hasRows) {
      const rows = await page.locator('table tbody tr').count().catch(() => 0)
      const m = v.match(/([\d,]+)\s+records?/i)
      const stated = m ? Number(m[1].replace(/,/g, '')) : null
      const isSlice = stated != null && rows < stated
      if (isSlice) {
        const saysSlice = /loaded|of [\d,]+|floor|not over all|scroll/i.test(v)
        record(saysSlice, 'analysis', `viewer "${decoded}" discloses that it shows a slice`,
          `${rows} rows of ${stated} — ${v.slice(0, 180)}`)
      } else {
        record(stated != null, 'analysis', `viewer "${decoded}" states its population`,
          stated == null ? v.slice(0, 180) : `${rows} rows, all ${stated} shown`)
      }
    }
  }

  // ---- Audit: verify chain, and the completeness wording -------------------
  await go(`/cases/${caseId}/audit`, 2400)
  const didVerify = await click('button', 'Verify chain', 2400)
  record(didVerify, 'audit', 'chain verification is reachable', didVerify ? '' : 'no control')
  if (didVerify) {
    const a = await bodyText()
    const intact = /chain intact/i.test(a)
    const broken = /chain broken/i.test(a)
    record(intact || broken, 'audit', 'states a verdict', a.slice(0, 140))
    if (intact) {
      // AUDIT-001: an unanchored verification must NOT read as complete, and the
      // head must be published so it CAN be anchored next time.
      record(/completeness not checked|cannot attest|not, on its own/i.test(a),
        'audit', 'completeness is stated as unchecked without an anchor', a.slice(0, 260))
      record(/chain head to anchor/i.test(a),
        'audit', 'publishes the head to anchor externally', a.slice(0, 200))
    } else if (broken) {
      // A broken chain has no verified head to publish, which is correct. What it
      // MUST do is name the reason precisely enough to act on — this environment
      // restarts the server with a fresh audit key over a persisted workspace,
      // which is exactly the key-rotation case DEPLOY-001 added the fingerprint
      // for, so the reason must name the variable that fixes it.
      record(/reason:/i.test(a), 'audit', 'a broken chain names its reason', a.slice(0, 200))
      record(/SEANCE_AUDIT_HMAC_KEY/i.test(a),
        'audit', 'the reason names the variable that would resolve it', a.slice(0, 300))
    }
    await shot('audit-verified', { settle: 800, fullPage: false })
  }

  // ---- Memory: a stage that did not run must say so, not show empty -------
  if (memoryCaseId) {
    await go(`/cases/${memoryCaseId}/memory/processes`, 3200)
    const m = await bodyText()
    record(/\d/.test(m), 'memory', 'process list renders', m.slice(0, 140))
    const floorStated = /floor, not a total|counts are a floor|incomplete/i.test(m)
    record(floorStated, 'memory', 'counts declare themselves a floor', m.slice(0, 220))
    await go(`/cases/${memoryCaseId}/memory/network`, 3000)
    const n = await bodyText()
    // The network stage cannot decode modern builds; it must SAY that.
    const saysWhy = /did not run|cannot be decoded|not analysed|no result/i.test(n)
    record(saysWhy, 'memory', 'a stage that did not run says why', n.slice(0, 240))
  }

  // ---- Not-found routes must be a stated condition, not a blank ------------
  await go(`/cases/${caseId}/no-such-screen`, 1800)
  const nf = await bodyText()
  // The product's wording is "No view at this address … Nothing is missing from
  // the case — the address itself matches no view in this product", which is a
  // better answer than "not found": it separates a bad address from missing
  // evidence. The check matches what it actually says.
  record(/no view at this address|not found|does not exist/i.test(nf),
    'not-found', 'states the condition, distinguishing a bad address from missing evidence',
    nf.slice(0, 160))
} catch (e) {
  record(false, 'harness', 'completed without throwing', String(e).slice(0, 300))
} finally {
  const failed = checks.filter((c) => !c.ok)
  fs.writeFileSync(
    path.join(outDir, 'interaction-report.json'),
    JSON.stringify({ total: checks.length, failed: failed.length, checks, problems }, null, 2),
  )
  console.log(`\n=== ${checks.length - failed.length}/${checks.length} checks passed ===`)
  for (const f of failed) console.log(`  FAIL ${f.screen} :: ${f.name} — ${f.detail}`)
  // A failing check has to fail the PROCESS, or this is a gate that cannot
  // fail. `documentation/UI_TESTING.md` §8.1 names this pass as the recommended
  // first CI step; wired in as it stood, CI would have gone green over every
  // failed check, which is worse than not running it — a green build asserting
  // something nobody checked.
  //
  // Zero checks is a failure too. The harness aborts loudly on a failed
  // precondition (a silent login failure once produced 28 screenshots of the
  // login page), and a run that recorded nothing is that abort, not a pass.
  process.exitCode = failed.length > 0 || checks.length === 0 ? 1 : 0
  await browser.close()
}
