// Layout check — a dependency-free stand-in for pixel visual regression.
//
// The defect that motivated visual regression was the "generic view" badge
// drawn across nine analysis card titles, unreadable and invisible to jsdom.
// That class of defect does not need an image diff to detect: it is two text
// elements whose bounding boxes INTERSECT. This finds them from the geometry
// the browser already computes, so it needs no image library and produces a
// reason rather than a pixel count — "these two elements overlap by 34px" is
// actionable; "0.3% of pixels differ" is not.
//
// It also catches two neighbours of the same class:
//   - text clipped by its own container (scrollWidth > clientWidth with no
//     ellipsis and no scrollbar), which is a value silently cut off; and
//   - text painted outside the viewport's right edge, which is the graph-label
//     defect in DOM form.
//
//   SEANCE_PASS=... node layout.mjs <caseId> <outDir> [width]
import { open, login, BASE } from './harness.mjs'
import fs from 'node:fs'
import path from 'node:path'

const [caseId, outDir, widthArg] = process.argv.slice(2)
const width = Number(widthArg || 1440)

// Every case surface that renders text worth reading.
const ROUTES = [
  ['dashboard', ''],
  ['timeline', '/timeline'],
  ['search', '/search?q=the'],
  ['analysis', '/analysis'],
  ['gallery', '/gallery'],
  ['audit', '/audit'],
  ['bookmarks', '/bookmarks'],
  ['filters', '/filters'],
  ['hash-sets', '/hash-sets'],
  ['settings', '/settings'],
  ['help', '/help'],
]

/**
 * Collected in the page: leaf elements that paint their own text, with their
 * rects. Only leaves are compared, because an ancestor legitimately contains
 * its descendants and every such pair would otherwise be an "overlap".
 */
const COLLECT = () => {
  const out = []
  const els = document.querySelectorAll('body *')
  for (const el of els) {
    // Leaf-ish: no element child that itself carries text.
    const kids = Array.from(el.children)
    const hasTextChild = kids.some((k) => (k.textContent || '').trim().length > 0)
    if (hasTextChild) continue
    const text = (el.textContent || '').trim()
    if (!text) continue
    // Per-LINE boxes, not the union box. `getBoundingClientRect()` on an inline
    // element that wraps returns a rectangle spanning every line it occupies —
    // including the empty gutter to the right of the first line and to the left
    // of the last — so a wrapped <strong> in a paragraph "overlaps" every other
    // inline on those lines. It does not: it paints only its line boxes. The
    // first run reported four such pairs in the help text, all imaginary.
    const rects = Array.from(el.getClientRects())
    if (!rects.length) continue
    const r = rects[0]
    if (rects.some((q) => q.width < 2 || q.height < 2) && rects.length === 1) continue
    if (r.width < 2 || r.height < 2) continue
    const cs = getComputedStyle(el)
    if (cs.visibility === 'hidden' || cs.opacity === '0' || cs.display === 'none') continue

    // Only elements actually PAINTED where they claim to be. Two things
    // otherwise produce pure noise, and did on the first run: content inside a
    // collapsed panel still reports a rect, and an item scrolled out of the
    // sidebar's own overflow still reports one at its unscrolled position.
    // Both then "overlap" whatever is drawn there now. A hit test at the
    // element's centre settles it: if the topmost element at that point is not
    // this element, an ancestor of it, or a descendant of it, this element is
    // not what the examiner sees there.
    if (r.bottom < 0 || r.top > innerHeight || r.right < 0 || r.left > innerWidth) continue
    const cx = r.x + r.width / 2
    const cy = r.y + r.height / 2
    if (cx < 0 || cy < 0 || cx > innerWidth || cy > innerHeight) continue
    // The topmost element at this point must be THIS element or something
    // inside it. Accepting an ancestor too (`top.contains(el)`) was wrong: a
    // collapsed panel's children keep their rects, and the hit test then
    // returns a shared wrapper, which contains them — so every collapsed
    // control "overlapped" whatever is drawn there now. Ten such pairs were
    // reported on the search screen, whose two panels are visibly shut.
    const top = document.elementFromPoint(cx, cy)
    if (!top || !(top === el || el.contains(top))) continue

    // A wide table is allowed to run past the viewport when it scrolls inside
    // its own container; that is the documented pattern, not a defect.
    let scrollableAncestor = false
    // An element in a FIXED or STICKY layer is an overlay — the status bar, a
    // modal, a sticky header. Ordinary content scrolling underneath one is how
    // the page is supposed to work, not two things drawn on top of each other,
    // so pairs involving an overlay are not overlaps. (Centre-point hit testing
    // does not catch this on its own: a tall row whose centre is clear can still
    // have its bottom edge under the bar.)
    let overlay = false
    for (let p = el.parentElement; p; p = p.parentElement) {
      const pcs = getComputedStyle(p)
      if (pcs.overflowX === 'auto' || pcs.overflowX === 'scroll') scrollableAncestor = true
      if (pcs.position === 'fixed' || pcs.position === 'sticky') overlay = true
    }
    const ecs = getComputedStyle(el)
    if (ecs.position === 'fixed' || ecs.position === 'sticky') overlay = true

    // Clip each line box to the nearest scrolling ancestor's visible area. An
    // element is only PAINTED inside its scroll container: a table row near the
    // bottom of a scrolling panel has a rect that extends past it, and comparing
    // the unclipped rect made such rows "overlap" the footer below the panel.
    // Four pairs were reported that way at 1024px, where the screen is correct.
    let clip = null
    for (let p = el.parentElement; p; p = p.parentElement) {
      const pcs = getComputedStyle(p)
      const scrolls = /(auto|scroll)/.test(pcs.overflowY) || /(auto|scroll)/.test(pcs.overflowX)
      if (scrolls && p.clientHeight > 0) { clip = p.getBoundingClientRect(); break }
    }
    const clipped = (q) => {
      if (!clip) return q
      const x = Math.max(q.x, clip.x)
      const y = Math.max(q.y, clip.y)
      const r2 = Math.min(q.x + q.width, clip.x + clip.width)
      const b2 = Math.min(q.y + q.height, clip.y + clip.height)
      return { x, y, width: r2 - x, height: b2 - y }
    }

    // One entry per painted line box.
    for (const raw of rects) {
      const q = clipped(raw)
      if (q.width < 2 || q.height < 2) continue
      out.push({
        scrollableAncestor,
        overlay,
        text: text.slice(0, 60),
        tag: el.tagName.toLowerCase(),
        cls: (el.className && String(el.className).slice(0, 60)) || '',
        x: q.x, y: q.y, w: q.width, h: q.height,
        scrollW: el.scrollWidth,
        clientW: el.clientWidth,
        overflow: cs.overflowX,
        ellipsis: cs.textOverflow === 'ellipsis',
        multiline: rects.length > 1,
      })
    }
    continue
    // eslint-disable-next-line no-unreachable
    out.push({
      scrollableAncestor,
      text: text.slice(0, 60),
      tag: el.tagName.toLowerCase(),
      cls: (el.className && String(el.className).slice(0, 60)) || '',
      x: r.x, y: r.y, w: r.width, h: r.height,
      // Clipping: content wider than the box, with nothing to reveal it.
      scrollW: el.scrollWidth,
      clientW: el.clientWidth,
      overflow: cs.overflowX,
      ellipsis: cs.textOverflow === 'ellipsis',
    })
  }
  return out
}

const overlapArea = (a, b) => {
  const ox = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x)
  const oy = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y)
  return ox > 0 && oy > 0 ? ox * oy : 0
}

const findings = []
// Text elements actually examined, so a run that examined none can be told
// from a run that found nothing wrong. They look identical in the report.
let checkedElements = 0
const { browser, page } = await open({ outDir, width, height: 900 })

try {
  await login(page)
  for (const [name, sub] of ROUTES) {
    await page.goto(`${BASE}/cases/${caseId}${sub}`, { waitUntil: 'domcontentloaded' }).catch(() => {})
    await page.waitForTimeout(2200)
    const boxes = await page.evaluate(COLLECT).catch(() => [])

    // 1. Two text leaves painted on top of one another.
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i]
        const b = boxes[j]
        if (a.overlay || b.overlay) continue // content under an overlay is normal
        const area = overlapArea(a, b)
        if (!area) continue
        // Ignore slivers: a 1–2px touch is normal from borders and rounding.
        const smaller = Math.min(a.w * a.h, b.w * b.h)
        if (area < Math.max(24, smaller * 0.2)) continue
        findings.push({
          screen: name, kind: 'overlap',
          detail: `"${a.text}" (${a.tag}.${a.cls}) overlaps "${b.text}" (${b.tag}.${b.cls}) by ${Math.round(area)}px²`,
        })
      }
    }

    // 2. Text clipped by its own box with no ellipsis and no scroll.
    for (const b of boxes) {
      const clipped = b.scrollW > b.clientW + 2
      const revealed = b.ellipsis || b.overflow === 'auto' || b.overflow === 'scroll'
      if (clipped && !revealed) {
        findings.push({
          screen: name, kind: 'clipped',
          detail: `"${b.text}" (${b.tag}.${b.cls}) is ${b.scrollW - b.clientW}px wider than its box, with no ellipsis and no scroll`,
        })
      }
    }

    // 3. Text painted past the right edge of the viewport.
    for (const b of boxes) {
      if (b.scrollableAncestor) continue // scrolls inside its own container
      if (b.x + b.w > width + 2) {
        findings.push({
          screen: name, kind: 'offscreen',
          detail: `"${b.text}" (${b.tag}.${b.cls}) extends ${Math.round(b.x + b.w - width)}px past the right edge with no scrollable container`,
        })
      }
    }
    checkedElements += boxes.length
    console.log(`${name}: ${boxes.length} text elements checked`)
  }
} finally {
  fs.mkdirSync(outDir, { recursive: true })
  fs.writeFileSync(path.join(outDir, 'layout-report.json'), JSON.stringify({ width, findings }, null, 2))
  const byKind = findings.reduce((m, f) => ((m[f.kind] = (m[f.kind] || 0) + 1), m), {})
  console.log(`\n=== ${findings.length} layout findings at ${width}px ===`, JSON.stringify(byKind))
  for (const f of findings.slice(0, 40)) console.log(`  [${f.kind}] ${f.screen}: ${f.detail}`)
  // Reported, not asserted — and the exit code says which. This is an
  // exploratory tool rather than a gate (UI_TESTING.md §4C records the residual
  // false positives at 1024px that keep it one), so findings do not fail the
  // process; a run that examined NOTHING does, because that is a broken harness
  // reporting a clean screen.
  process.exitCode = checkedElements === 0 ? 1 : 0
  await browser.close()
}
