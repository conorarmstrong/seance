import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

/**
 * Measuring a colour pairing as the screen actually draws it.
 *
 * This module is the instrument. The tests that point it at things are
 * app/contrast.test.ts — every declared pairing in every stylesheet, plus the
 * rendered surfaces listed in its RENDERED — and
 * pages/files/selectedRowContrast.test.tsx, which pins the one pairing that
 * caused all of this. It holds no assertions of its own, and the ledgers that
 * excuse things (UNMEASURABLE, NOT_APPLIED) deliberately stay with the tests
 * that argue them: an excuse belongs next to the assertion it weakens.
 *
 * It is a plain module rather than a helper inside one of those test files
 * because importing one `.test` file from another executes its module body
 * during the importer's collection: every `describe` would re-register and its
 * tests would run twice, reported under the wrong filename. A suite that
 * reports one test under two filenames makes a failure impossible to locate.
 *
 * The two halves it serves are different instruments and it is worth saying
 * which is which. Reading a stylesheet answers "what colour is this text" and
 * "what does this rule paint behind its own text". It cannot answer "what is
 * behind this text", because the ground may be painted by an ancestor five
 * elements up, through two translucent tints and an `opacity`, and a `.css`
 * file does not say what is above what. That question needs a rendered
 * document, which is why {@link chainOf} and {@link composite} take an Element
 * and why nothing here can be run over the stylesheets alone.
 */

/** WCAG AA for text under 18.66px, which is all of this product's data text. */
export const AA_SMALL_TEXT = 4.5

// Resolved from the Vitest root (the frontend package) rather than from
// import.meta.url, which the jsdom environment rewrites to an http: URL.
export const srcRoot = resolve(process.cwd(), 'src')
const cssPath = join(srcRoot, 'index.css')

/** Every stylesheet under src/, so a new one is covered the day it is added. */
export function stylesheets(): string[] {
  const found: string[] = []
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry)
      if (statSync(full).isDirectory()) walk(full)
      else if (entry.endsWith('.css')) found.push(full)
    }
  }
  walk(srcRoot)
  return found.sort()
}

/**
 * Blank a comment out without moving what follows it onto another line.
 *
 * Deleting it outright would shift every line number below it, and those line
 * numbers are most of the value of a failure message: they name the
 * declaration to go and edit.
 */
export function stripComments(css: string): string {
  return css.replace(/\/\*[\s\S]*?\*\//g, (block) =>
    block.replace(/[^\n]/g, ' '),
  )
}

/**
 * Every custom property index.css defines, with its value as written.
 *
 * Values are kept raw rather than filtered to hex, so a token defined as an
 * rgba() tint is reported as "not an opaque colour" rather than as "undefined".
 * Those are different faults and would send someone looking in the wrong place.
 */
export function tokens(): Map<string, string> {
  const css = stripComments(readFileSync(cssPath, 'utf8'))
  const map = new Map<string, string>()
  for (const match of css.matchAll(/(--[\w-]+):\s*([^;]+);/g)) {
    map.set(match[1], match[2].trim())
  }
  return map
}

function relativeLuminance(hex: string): number {
  const channels = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
  const [r, g, b] = channels.map((c) =>
    c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4),
  )
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

/** WCAG 2.1 contrast ratio, 1:1 (identical) to 21:1 (black on white). */
export function contrastRatio(a: string, b: string): number {
  const la = relativeLuminance(a)
  const lb = relativeLuminance(b)
  const [lighter, darker] = la > lb ? [la, lb] : [lb, la]
  return (lighter + 0.05) / (darker + 0.05)
}

/**
 * A colour as CSS wrote it: the hue, plus how much of what is behind it still
 * shows through. Alpha is carried rather than dropped, because dropping it is
 * exactly the assumption that hid `.error-note`.
 */
export interface Ink {
  /** `#rrggbb`, before alpha is applied. */
  hex: string
  /** 0 to 1. Under 1 and it has to be composited before it can be measured. */
  alpha: number
}

export const channelsOf = (hex: string) =>
  [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16))

export const toHex = (parts: number[]) =>
  `#${parts.map((c) => Math.round(c).toString(16).padStart(2, '0')).join('')}`

/** `layer` painted over the opaque colour `under`, as source-over would. */
export function flatten(layer: Ink, under: string): string {
  if (layer.alpha >= 1) return layer.hex
  const front = channelsOf(layer.hex)
  const back = channelsOf(under)
  return toHex(
    front.map((c, i) => c * layer.alpha + back[i] * (1 - layer.alpha)),
  )
}

/** Split on top-level commas, so a nested `rgba(...)` stays in one piece. */
function topLevelParts(list: string): string[] {
  const parts: string[] = []
  let depth = 0
  let current = ''
  for (const char of list) {
    if (char === '(') depth += 1
    if (char === ')') depth -= 1
    if (char === ',' && depth === 0) {
      parts.push(current)
      current = ''
    } else current += char
  }
  parts.push(current)
  return parts.map((part) => part.trim()).filter(Boolean)
}

/**
 * Resolve a CSS colour value to an {@link Ink}, following `var()` and its
 * fallback, `rgb()`/`rgba()`, and `color-mix()` in the one form this codebase
 * uses — a percentage of a colour against `transparent`, which is a tint.
 *
 * Returns null for anything else: a keyword like `inherit`, or a token
 * index.css does not define and that carries no fallback. Callers must account
 * for every null rather than skip it, which is what `UNMEASURABLE` is for.
 */
export function resolveInk(
  value: string,
  map: Map<string, string>,
  depth = 0,
): Ink | null {
  const v = value.replace(/!important/, '').trim()
  if (depth > 8) return null
  if (v.toLowerCase() === 'transparent') return { hex: '#000000', alpha: 0 }
  if (/^#[0-9a-f]{6}$/i.test(v)) return { hex: v.toLowerCase(), alpha: 1 }
  if (/^#[0-9a-f]{3}$/i.test(v)) {
    return {
      hex: `#${[1, 2, 3].map((i) => v[i] + v[i]).join('')}`.toLowerCase(),
      alpha: 1,
    }
  }

  const rgb = /^rgba?\(([^()]+)\)$/i.exec(v)
  if (rgb) {
    const parts = rgb[1].split(/[,\s/]+/).filter(Boolean).map(Number)
    if (parts.length < 3 || parts.slice(0, 3).some(Number.isNaN)) return null
    return {
      hex: toHex(parts.slice(0, 3)),
      alpha: parts.length > 3 && !Number.isNaN(parts[3]) ? parts[3] : 1,
    }
  }

  const mix = /^color-mix\(\s*in\s+[\w-]+\s*,([\s\S]+)\)$/i.exec(v)
  if (mix) {
    const parts = topLevelParts(mix[1])
    if (parts.length !== 2) return null
    const share = (part: string): [string, number | null] => {
      const percent = /^([\s\S]+?)\s+([\d.]+)%$/.exec(part)
      return percent ? [percent[1], parseFloat(percent[2]) / 100] : [part, null]
    }
    const [firstRaw, firstShare] = share(parts[0])
    const [secondRaw, secondShare] = share(parts[1])
    const first = resolveInk(firstRaw, map, depth + 1)
    const second = resolveInk(secondRaw, map, depth + 1)
    if (!first || !second) return null
    const weight = firstShare ?? (secondShare !== null ? 1 - secondShare : 0.5)
    const front = channelsOf(first.hex)
    const back = channelsOf(second.hex)
    return {
      hex: toHex(front.map((c, i) => c * weight + back[i] * (1 - weight))),
      alpha: first.alpha * weight + second.alpha * (1 - weight),
    }
  }

  const varCall = /^var\(\s*(--[\w-]+)\s*(?:,([\s\S]+))?\)$/.exec(v)
  if (!varCall) return null
  const [, name, fallback] = varCall
  const defined = map.get(name)
  if (defined !== undefined) {
    const resolved = resolveInk(defined, map, depth + 1)
    if (resolved) return resolved
  }
  return fallback ? resolveInk(fallback, map, depth + 1) : null
}

/** An opaque colour, or null — for the surfaces, which have to be opaque. */
export function resolveColor(value: string, map: Map<string, string>): string | null {
  const ink = resolveInk(value, map)
  return ink && ink.alpha >= 1 ? ink.hex : null
}

/**
 * What a rule paints behind its own text.
 *
 * `unpainted` is not a failure to read the CSS: `background: none`, a fully
 * transparent one, and no background declaration at all all mean the text sits
 * on whatever surface an ancestor painted, so it answers to all four of them.
 * `unreadable` is the real hole, and it has to be argued for in words.
 */
export type Ground =
  | { kind: 'unpainted' }
  | { kind: 'painted'; layers: Ink[] }
  | { kind: 'unreadable'; value: string }

const NO_GROUND = new Set(['none', 'initial', 'unset', 'revert', 'inherit'])

export function resolveGround(value: string, map: Map<string, string>): Ground {
  const v = value.replace(/!important/, '').trim()
  if (NO_GROUND.has(v.toLowerCase())) return { kind: 'unpainted' }

  // A gradient is not one ground but every stop it names, and text has to
  // clear all of them. Anything in the list that is not a colour — an angle, a
  // stop position — does not resolve and drops out.
  if (/gradient\(/i.test(v)) {
    const layers = topLevelParts(v.slice(v.indexOf('(') + 1, v.lastIndexOf(')')))
      .map((part) => part.replace(/\s+[\d.]+(px|%|em|rem)\s*$/i, '').trim())
      .map((part) => resolveInk(part, map))
      .filter((ink): ink is Ink => ink !== null)
    return layers.length > 0
      ? { kind: 'painted', layers }
      : { kind: 'unreadable', value: v }
  }

  const ink = resolveInk(v, map)
  if (!ink) return { kind: 'unreadable', value: v }
  return ink.alpha === 0
    ? { kind: 'unpainted' }
    : { kind: 'painted', layers: [ink] }
}

/**
 * An `opacity` as a number, or null for one written in a form this file cannot
 * read. Percentages are legal CSS for it, so both forms are accepted.
 */
export function resolveOpacity(value: string): number | null {
  const v = value.replace(/!important/, '').trim()
  const percent = /^([\d.]+)%$/.exec(v)
  const n = percent ? parseFloat(percent[1]) / 100 : Number(v)
  // Out-of-range values are clamped by the browser rather than ignored, but
  // this codebase writes none, and reading one as null sends whoever added it
  // here rather than letting it be silently reinterpreted.
  if (!Number.isFinite(n) || n < 0 || n > 1) return null
  return n
}
export interface StyleRule {
  selector: string
  /** Source position, to break ties between equal specificities. */
  order: number
  color?: string
  background?: string
  opacity?: string
}

export type StyleProperty = 'color' | 'background' | 'opacity'

/**
 * Blank out the body of every `@keyframes` block, newlines kept.
 *
 * A keyframe is a selector-shaped thing (`from`, `to`, `50%`) that is not a
 * selector, and its declarations describe an animation rather than a resting
 * state. `50%` is not even parseable as one. Measuring the resting state is
 * the right call — an animated frame is transient by definition — so the
 * blocks are removed before anything tries to match them.
 */
function stripKeyframes(css: string): string {
  return stripAtRuleBodies(css, /@(-\w+-)?keyframes[^{]*\{/i)
}

/**
 * Blank out the body of every at-rule this half does not evaluate.
 *
 * `@media`, `@supports` and `@container` all say "these rules, but only
 * sometimes", and this half has no way to answer the "sometimes": jsdom
 * reports no viewport size worth trusting and no user preferences, so a
 * `@media print` palette or a narrow-screen override would be applied here as
 * though it were always on. Applying it would be a false positive with a fuse
 * in it, so the rules are dropped — and dropped visibly, by
 * {@link conditionalColourRules}, which names every one that touches a colour,
 * a ground or an opacity so that dropping it is a decision on the record
 * instead of a silence.
 */
function stripAtRuleBodies(css: string, opener: RegExp): string {
  let out = css
  for (;;) {
    const at = opener.exec(out)
    if (!at) return out
    let depth = 1
    let i = at.index + at[0].length
    while (depth > 0 && i < out.length) {
      if (out[i] === '{') depth += 1
      else if (out[i] === '}') depth -= 1
      i += 1
    }
    out =
      out.slice(0, at.index) +
      out.slice(at.index, i).replace(/[^\n]/g, ' ') +
      out.slice(i)
  }
}

/** The stylesheets as this half reads them: no comments, no unevaluated at-rules. */
function applicableCss(file: string): string {
  return stripAtRuleBodies(
    stripKeyframes(stripComments(readFileSync(file, 'utf8'))),
    /@(media|supports|container)[^{]*\{/i,
  )
}

/** Every rule under src/ that declares a colour, a ground or an opacity. */
export function styleRules(): StyleRule[] {
  const all: StyleRule[] = []
  for (const file of stylesheets()) {
    const css = applicableCss(file)
    for (const block of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
      const selector = block[1].trim()
      if (selector.startsWith('@') || selector === '') continue
      const declarations = [...block[2].matchAll(/([-a-z]+)\s*:\s*([^;]+)/g)]
      const last = (...names: string[]) =>
        declarations
          .filter(([, prop]) => names.includes(prop))
          .map(([, , value]) => value.trim())
          .pop()
      const rule: StyleRule = { selector, order: all.length }
      rule.color = last('color')
      rule.background = last('background', 'background-color')
      rule.opacity = last('opacity')
      if (rule.color || rule.background || rule.opacity) all.push(rule)
    }
  }
  return all
}

export function conditionalColourRules(): string[] {
  const found: string[] = []
  for (const file of stylesheets()) {
    const css = stripKeyframes(stripComments(readFileSync(file, 'utf8')))
    for (const at of css.matchAll(/@(media|supports|container)[^{]*\{/gi)) {
      let depth = 1
      let i = (at.index as number) + at[0].length
      while (depth > 0 && i < css.length) {
        if (css[i] === '{') depth += 1
        else if (css[i] === '}') depth -= 1
        i += 1
      }
      const body = css.slice((at.index as number) + at[0].length, i)
      for (const block of body.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
        if (/(^|;|\s)(color|background|background-color|opacity)\s*:/.test(block[2])) {
          found.push(
            `${relative(srcRoot, file)}: ${at[0].replace(/\s*\{$/, '')} { ${block[1].trim()} }`,
          )
        }
      }
    }
  }
  return found.sort()
}

/** (id, class/attribute/pseudo-class, element) counts, as CSS ranks them. */
function specificity(selector: string): number {
  const ids = (selector.match(/#[\w-]+/g) ?? []).length
  const classes = (selector.match(/\.[\w-]+|\[[^\]]+\]|:[\w-]+(?!:)/g) ?? [])
    .length
  const elements = (selector.match(/(^|[\s>+~])[a-z]+/gi) ?? []).length
  return ids * 10000 + classes * 100 + elements
}

/**
 * One selector of a list, with the cheap necessary conditions for it to match.
 *
 * `element.matches` against every rule in the product for every element in a
 * rendered page is tens of millions of calls and minutes of wall clock. The
 * rightmost compound of a selector states what the element ITSELF must be, so
 * a class it does not carry or a tag it is not rules the whole selector out
 * before jsdom is asked. This is a filter and not a second matcher: everything
 * it lets through is still put to `element.matches`, so it can make the pass
 * faster but cannot make it answer differently.
 */
interface SelectorPart {
  text: string
  rank: number
  /** Classes the element itself must carry. */
  classes: string[]
  /** The tag the element itself must be, or null for any. */
  tag: string | null
}

function compilePart(text: string): SelectorPart {
  const last = text.split(/[\s>+~]+/).filter(Boolean).pop() ?? text
  // `:not(.a)` does not require `.a` — it forbids it — so the arguments of a
  // functional pseudo-class contribute nothing to what is required here.
  const bare = last.replace(/:[\w-]+\([^)]*\)/g, '')
  const tag = /^([a-z][\w-]*)/i.exec(bare)
  return {
    text,
    rank: specificity(text),
    classes: [...bare.matchAll(/\.([\w-]+)/g)].map((m) => m[1]),
    tag: tag ? tag[1].toLowerCase() : null,
  }
}

/** A rule with its selector list compiled and its declarations kept. */
interface Matcher {
  parts: SelectorPart[]
  order: number
  color?: string
  background?: string
  opacity?: string
}

function compile(all: StyleRule[]): Matcher[] {
  return all.map((rule) => ({
    ...rule,
    parts: rule.selector
      .split(',')
      .map((part) => part.trim())
      .filter(Boolean)
      .map(compilePart),
  }))
}

/** Selectors jsdom refuses to parse, kept so they are reported, not lost. */
export const unparseable = new Set<string>()

/**
 * How strongly a rule claims one element, or null if it does not match it.
 *
 * A selector LIST is ranked part by part rather than as one string: the cascade
 * ranks `.a, .b .c` by whichever half matched, and summing them would let a
 * rule that happens to name five selectors outrank one that genuinely wins.
 */
function claimOn(element: Element, parts: SelectorPart[]): number | null {
  let best: number | null = null
  for (const part of parts) {
    if (part.tag && element.tagName.toLowerCase() !== part.tag) continue
    if (part.classes.some((name) => !element.classList.contains(name))) continue
    let matches = false
    try {
      matches = element.matches(part.text)
    } catch {
      // A selector jsdom cannot parse matches nothing here. It is recorded so
      // that a stylesheet full of them cannot quietly reduce this half to
      // measuring nothing.
      unparseable.add(part.text)
      continue
    }
    if (!matches) continue
    if (best === null || part.rank > best) best = part.rank
  }
  return best
}

/**
 * The class {@link asHovered} substitutes for `:hover`.
 *
 * jsdom performs no pointer input, so `element.matches(':hover')` is false for
 * every element in every rendered document and a hover rule is simply absent
 * from the cascade this file resolves. That is tolerable for the rule's OWN
 * text — the stylesheet pass holds `.ctx-menu-item:hover`'s `color` to the
 * floor against every surface its fill can sit on — but it is not tolerable
 * for text INSIDE a hovered element. A hover fill is a ground an ancestor
 * paints, so the only pass that can measure it is this one, and the only way
 * to measure it here is to put the element into the state.
 *
 * The name is deliberately not a product class: nothing in src/ can match it,
 * so substituting it cannot make a real rule apply that would not have.
 */
export const HOVER_PROBE_CLASS = 'contrast-probe-hover'

/**
 * The rules as they apply while something is hovered.
 *
 * Every `:hover` becomes {@link HOVER_PROBE_CLASS}, which is a plain class the
 * test then puts on the element the pointer is over — and, because the browser
 * hovers an element together with every ancestor that contains it, on that
 * element's ancestors too (see {@link markHovered}).
 *
 * Two properties make the substitution faithful rather than approximate.
 * `:hover` and a class rank identically in the cascade, so no rule changes
 * which one it beats; and the replacement is textual over the whole selector
 * list, so `.a:hover, .b` keeps `.b` and `:not(:hover)` keeps its meaning.
 */
export function asHovered(all: StyleRule[]): StyleRule[] {
  return all.map((rule) => ({
    ...rule,
    selector: rule.selector.replaceAll(':hover', `.${HOVER_PROBE_CLASS}`),
  }))
}

/**
 * Put `element` into the hovered state, and its ancestors with it.
 *
 * The ancestors are not a nicety. `:hover` matches every element containing
 * the pointer, so a menu item under the pointer is hovered inside a menu that
 * is also hovered — and a hover fill on the CONTAINER is exactly the ground
 * that this pass exists to find. Marking only the leaf would measure a
 * composite the screen never draws.
 *
 * Returns the undo, so a document can be measured in both states.
 */
export function markHovered(element: Element): () => void {
  const marked: Element[] = []
  for (let node: Element | null = element; node; node = node.parentElement) {
    node.classList.add(HOVER_PROBE_CLASS)
    marked.push(node)
  }
  return () => {
    for (const node of marked) node.classList.remove(HOVER_PROBE_CLASS)
  }
}

/** The declarations that win for one element. */
type Style = Partial<Record<StyleProperty, string>>

const STYLE_PROPERTIES: StyleProperty[] = ['color', 'background', 'opacity']

/**
 * A reader for the winning declarations of an element, memoised per element.
 *
 * The cascade is resolved for all three properties in one pass over the rules
 * rather than one pass each, and the climb asks about the same ancestors over
 * and over — `.ft-wrap` is an ancestor of every label in the tree — so the
 * answer is cached against the element.
 */
export function styleReader(all: StyleRule[]): (element: Element) => Style {
  const compiled = compile(all)
  const cache = new WeakMap<Element, Style>()
  return (element) => {
    const hit = cache.get(element)
    if (hit) return hit
    const best: Partial<
      Record<StyleProperty, { rank: number; order: number; value: string }>
    > = {}
    for (const rule of compiled) {
      let rank: number | null = null
      for (const property of STYLE_PROPERTIES) {
        const value = rule[property]
        if (value === undefined) continue
        if (rank === null) {
          rank = claimOn(element, rule.parts)
          if (rank === null) break
        }
        const held = best[property]
        if (!held || rank > held.rank || (rank === held.rank && rule.order > held.order)) {
          best[property] = { rank, order: rule.order, value }
        }
      }
    }
    const style: Style = {}
    for (const property of STYLE_PROPERTIES) {
      const won = best[property]
      if (won) style[property] = won.value
    }
    cache.set(element, style)
    return style
  }
}

/**
 * The colour an element's own text is drawn in.
 *
 * `color` inherits, so `color: inherit` is not a colour this can fail to read —
 * it is the parent's colour, and the climb ends at index.css's `body`, which
 * sets --text-0. Reading `inherit` as unreadable would have put a real
 * declaration into an excuse ledger.
 */
export function inkOf(
  element: Element,
  read: (element: Element) => Style,
  map: Map<string, string>,
): { declaredAs: string; ink: Ink | null } | null {
  let node: Element | null = element
  let declaredAs: string | undefined
  while (node) {
    const value = read(node).color
    if (value !== undefined && value.replace(/!important/, '').trim() !== 'inherit') {
      declaredAs ??= value
      return { declaredAs, ink: resolveInk(value, map) }
    }
    if (value !== undefined) declaredAs ??= value
    if (declaredAs === undefined) return null
    node = node.parentElement
  }
  return { declaredAs: declaredAs as string, ink: null }
}

/** A colour in premultiplied form, so compositing is addition. */
export interface Premul {
  c: [number, number, number]
  a: number
}

export const TRANSPARENT: Premul = { c: [0, 0, 0], a: 0 }

export function premul(ink: Ink): Premul {
  const [r, g, b] = channelsOf(ink.hex)
  return { c: [r * ink.alpha, g * ink.alpha, b * ink.alpha], a: ink.alpha }
}

/** `top` drawn over `bottom`, source-over. */
export function over(top: Premul, bottom: Premul): Premul {
  return {
    c: top.c.map((v, i) => v + bottom.c[i] * (1 - top.a)) as Premul['c'],
    a: top.a + bottom.a * (1 - top.a),
  }
}

/** A whole group faded by its element's `opacity`. */
export function fade(layer: Premul, opacity: number): Premul {
  return {
    c: layer.c.map((v) => v * opacity) as Premul['c'],
    a: layer.a * opacity,
  }
}

/** One element of the climb: what it paints, and what it fades. */
export interface Layer {
  ink: Ink | null
  opacity: number
  from: Element
}

/** What one element paints behind whatever is inside it. */
function fillOf(
  element: Element,
  read: (element: Element) => Style,
  map: Map<string, string>,
): { ink: Ink | null; unreadable?: string } {
  const value = read(element).background
  if (value === undefined) return { ink: null }
  const ground = resolveGround(value, map)
  if (ground.kind === 'unpainted') return { ink: null }
  if (ground.kind === 'unreadable') return { ink: null, unreadable: value }
  // A gradient is more than one ground, and which of its stops is behind a
  // given glyph is a question about geometry this cannot answer. The
  // stylesheet pass holds every stop of a rule's own gradient to the floor;
  // here it is reported rather than reduced to a guess.
  if (ground.layers.length !== 1) return { ink: null, unreadable: value }
  return { ink: ground.layers[0] }
}

/** The element and its ancestors, innermost first, with what each contributes. */
export function chainOf(
  element: Element,
  read: (element: Element) => Style,
  map: Map<string, string>,
): { chain: Layer[]; unreadable: string[] } {
  const chain: Layer[] = []
  const unreadable: string[] = []
  let node: Element | null = element
  while (node) {
    const fill = fillOf(node, read, map)
    if (fill.unreadable) {
      unreadable.push(`${nameOf(node)}: background ${fill.unreadable}`)
    }
    const value = read(node).opacity
    const opacity = value === undefined ? 1 : resolveOpacity(value)
    if (opacity === null) unreadable.push(`${nameOf(node)}: opacity ${value}`)
    chain.push({ ink: fill.ink, opacity: opacity ?? 1, from: node })
    node = node.parentElement
  }
  return { chain, unreadable }
}

/**
 * `seed` composited outward through the chain, or null if the climb never
 * reaches an opaque layer.
 *
 * Both pixels the floor compares come from this one function with two seeds:
 * the text is the seed for the foreground, and nothing at all is the seed for
 * the ground beside it. That is what makes `opacity` come out right in a
 * nested tree — an ancestor's opacity fades its own fill AND everything inside
 * it, while an element's own opacity fades its text but not its grandparent's
 * fill, and running one loop with two seeds gets both without a second
 * formula to keep in step with the first.
 */
export function composite(seed: Premul, chain: Layer[]): string | null {
  let acc = seed
  for (const { ink, opacity } of chain) {
    if (ink && ink.alpha > 0) acc = over(acc, premul(ink))
    if (opacity < 1) acc = fade(acc, opacity)
  }
  // Never reached anything opaque: there is no ground, and the honest answer
  // is to say so rather than to assume the page surface.
  if (acc.a < 0.999) return null
  return toHex(acc.c.map((v) => v / acc.a))
}

/** `div.ft-row.selected`, for a message that names the element to go and fix. */
export function nameOf(element: Element): string {
  // `className` on an SVG element is an SVGAnimatedString, which stringifies
  // to "[object SVGAnimatedString]"; the attribute reads the same for both.
  const classes = (element.getAttribute('class') ?? '').trim()
  return `${element.tagName.toLowerCase()}${classes ? `.${classes.replace(/\s+/g, '.')}` : ''}`
}
/**
 * The two pixels the floor compares — the text, and the ground beside it —
 * for one rule, one fill of its own and one opaque surface under it.
 *
 * `opacity` is not a property of the text. It is a property of the element:
 * the browser draws the element whole — its fill, then its text on top — and
 * composites that group onto what is behind it at that alpha. Two consequences,
 * and both of them matter:
 *
 *  - the fill fades too, so a rule that fades an opaque fill no longer has a
 *    ground independent of the surface beneath it, and
 *  - the text is composited over the fill INSIDE the group and only then
 *    faded. Fading the text onto an already-faded ground is a different sum,
 *    and a wrong one whenever a rule has both a translucent fill and an
 *    opacity, because it counts the fill twice.
 */
export function drawnAt(
  ink: Ink,
  fill: Ink,
  opacity: number,
  surface: string,
): { fg: string; ground: string } {
  const ground = flatten({ hex: fill.hex, alpha: fill.alpha * opacity }, surface)
  const covered = ink.alpha + fill.alpha * (1 - ink.alpha)
  const front = channelsOf(ink.hex)
  const back = channelsOf(fill.hex)
  const group: Ink =
    covered === 0
      ? { hex: surface, alpha: 0 }
      : {
          hex: toHex(
            front.map(
              (c, i) =>
                (c * ink.alpha + back[i] * fill.alpha * (1 - ink.alpha)) /
                covered,
            ),
          ),
          alpha: covered,
        }
  return {
    fg: flatten({ hex: group.hex, alpha: group.alpha * opacity }, surface),
    ground,
  }
}

export interface TextUse {
  /** Path relative to src/, plus the line, so a failure names the edit to make. */
  where: string
  /** The declaration as written, e.g. `var(--accent-dim)`. */
  value: string
  /**
   * The ground the same rule paints. A rule that brings its own is either
   * inverted text on a fill — `color: var(--bg-0)` over `background:
   * var(--accent)` — or text on a tint, and answers to that rather than to the
   * bare page surfaces it will never be seen against.
   */
  ground: Ground
  /**
   * The `opacity` the same rule sets, 1 when it sets none, null when it sets
   * one this file cannot read.
   *
   * A colour and an opacity are two declarations, and reading only the first
   * measures a tone the screen never shows. That is not hypothetical: it hid
   * `.an-db-col-hide`, whose --text-2 at 0.6 draws at 2.66:1 on --bg-3 while
   * the token itself measures 4.83 there.
   */
  opacity: number | null
  /** The `opacity` as written, so a value that cannot be read can be named. */
  opacityValue: string
}

function lineOf(css: string, index: number): number {
  return css.slice(0, index).split('\n').length
}

/**
 * Every token-valued `color:` declaration under src/, with the ground its own
 * rule paints if it paints one.
 *
 * The regex matches innermost brace pairs only — a declaration block has no
 * braces inside it, while an `@media` wrapper does — so at-rules need no
 * handling of their own.
 */
export function textUses(map: Map<string, string>): TextUse[] {
  const uses: TextUse[] = []
  for (const file of stylesheets()) {
    const css = stripComments(readFileSync(file, 'utf8'))
    const name = relative(srcRoot, file)
    for (const block of css.matchAll(/\{([^{}]*)\}/g)) {
      const body = block[1]
      const bodyStart = (block.index as number) + 1
      const declarations = [...body.matchAll(/([-a-z]+)\s*:\s*([^;]+)/g)]
      // The last background declaration in the block wins, as the cascade
      // within a single rule does.
      const painted = declarations.filter(([, prop]) =>
        ['background', 'background-color', 'background-image'].includes(prop),
      )
      const ground: Ground = painted.length
        ? resolveGround(painted[painted.length - 1][2], map)
        : { kind: 'unpainted' }
      const faded = declarations
        .filter(([, prop]) => prop === 'opacity')
        .map(([, , value]) => value.trim())
        .pop()
      for (const declaration of declarations) {
        const [, prop, value] = declaration
        if (prop !== 'color' || !value.includes('var(--')) continue
        uses.push({
          where: `${name}:${lineOf(css, bodyStart + (declaration.index as number))}`,
          value: value.trim(),
          ground,
          opacity: faded === undefined ? 1 : resolveOpacity(faded),
          opacityValue: faded ?? '1',
        })
      }
    }
  }
  return uses
}


/**
 * The `--bg-N` surfaces a palette declares, as `(token name, hex)`.
 *
 * Derived rather than listed: a palette that grows a `--bg-4` must not widen
 * the set of grounds text can land on without widening what is checked.
 */
export function surfacesOf(map: Map<string, string>): (readonly [string, string])[] {
  return [...map.keys()]
    .filter((name) => /^--bg-\d+$/.test(name))
    .map((name) => [name, resolveColor(map.get(name) as string, map)] as const)
    .filter((pair): pair is readonly [string, string] => pair[1] !== null)
}

/**
 * Every pairing a use has to clear: the text as drawn, and the ground beside
 * it, for each fill the rule paints and each surface that fill can sit on.
 *
 * A translucent ground is not one ground but four: the tint composited over
 * each surface it can sit on. Treating it as "no ground" and measuring against
 * the bare surface is what hid `.error-note`, and treating it as an opaque
 * colour would be worse still. An `opacity` under 1 does the same thing to an
 * OPAQUE fill — the surface shows through it again — so a faded rule is four
 * pairings whatever its fill.
 */
export function drawingsFor(
  use: TextUse,
  ink: Ink,
  surfaces: (readonly [string, string])[],
): { label: string; fg: string; ground: string }[] {
  const opacity = use.opacity ?? 1
  const fills: (Ink | null)[] =
    use.ground.kind === 'painted' ? use.ground.layers : [null]
  return fills.flatMap((fill) => {
    // An opaque fill at full opacity hides the surface entirely, so it is one
    // ground rather than four — the only case where the surface under the rule
    // cannot reach the pixel.
    if (fill && fill.alpha >= 1 && opacity >= 1) {
      return [
        {
          label: `its own background ${fill.hex}`,
          ...drawnAt(ink, fill, 1, fill.hex),
        },
      ]
    }
    const nothing: Ink = { hex: '#000000', alpha: 0 }
    return surfaces.map(([name, hex]) => ({
      label: !fill
        ? name
        : fill.alpha >= 1
          ? `its own background ${fill.hex} over ${name}`
          : `its own ${Math.round(fill.alpha * 100)}% ${fill.hex} tint over ${name}`,
      ...drawnAt(ink, fill ?? nothing, opacity, hex),
    }))
  })
}

/**
 * Every pairing in the stylesheets that falls under the AA floor for one
 * palette, as a sorted list of sentences naming the file, the line, both
 * colours and the ratio.
 *
 * Empty is the only passing answer. There is no allowance and no ledger of
 * accepted exceptions: a pairing this can measure is either over the floor or
 * is a bug to fix before merge, and the useful form of the failure is the edit
 * it names.
 *
 * Taking the token map as an argument is what lets one instrument measure every
 * skin (`src/themes/palettes.ts`) rather than only the tokens in `index.css`.
 * Ten palettes checked by ten copies of this sweep would be ten chances for one
 * of them to drift into passing something the others catch.
 */
export function paletteFailures(map: Map<string, string>): string[] {
  const surfaces = surfacesOf(map)
  // Keyed by file rather than by line, so the ledger survives an unrelated edit
  // above it; the line still travels in the message, which is what someone
  // reading a failure actually needs.
  const failures = new Map<string, string>()
  for (const use of textUses(map)) {
    const ink = resolveInk(use.value, map)
    // A colour or an opacity this cannot read is accounted for by name by the
    // caller rather than waved through here; skipping them twice would be an
    // excuse.
    if (ink === null || use.opacity === null) continue
    // Text drawn at zero opacity is not drawn. There is no pairing to measure,
    // and inventing one would be the guard crying wolf.
    if (use.opacity === 0) continue
    const faded =
      use.opacity < 1 ? ` at ${Math.round(use.opacity * 100)}% opacity` : ''
    for (const { label, fg, ground } of drawingsFor(use, ink, surfaces)) {
      const ratio = Number(contrastRatio(fg, ground).toFixed(2))
      if (ratio >= AA_SMALL_TEXT) continue
      const file = use.where.slice(0, use.where.lastIndexOf(':'))
      failures.set(
        `${file}: ${use.value}${faded} on ${label}`,
        `${use.where}: color ${use.value}${faded} (${fg}) on ${label} (${ground}) is ${ratio}:1`,
      )
    }
  }
  return [...failures.values()].sort()
}
